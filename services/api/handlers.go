package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	cfg     Config
	db      *pgxpool.Pool
	limiter *limiter
}

var validStages = map[string]bool{"Prospecting": true, "Engaging": true, "Won": true, "Lost": true}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	// Unauthenticated: probes and login only.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.db.Ping(r.Context()); err != nil {
			writeErr(w, 503, "db unavailable")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /auth/login", s.login)

	// Authenticated routes: each declares the permission it needs.
	mux.Handle("GET /v1/me", s.protect("", s.me))
	mux.Handle("GET /v1/accounts", s.protect("accounts:read", s.listAccounts))
	mux.Handle("GET /v1/accounts/{id}", s.protect("accounts:read", s.getAccount))
	mux.Handle("GET /v1/opportunities", s.protect("opportunities:read", s.listOpportunities))
	mux.Handle("POST /v1/opportunities", s.protect("opportunities:write", s.createOpportunity))
	mux.Handle("PATCH /v1/opportunities/{id}/stage", s.protect("opportunities:write", s.updateStage))
	mux.Handle("GET /v1/analytics/pipeline", s.protect("analytics:read", s.pipeline))
	mux.Handle("GET /v1/audit", s.protect("audit:read", s.listAudit))

	// Order matters: requestID -> audit -> rateLimit -> routes.
	return requestID(s.audit(s.rateLimit(mux)))
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, principalFrom(r))
}

// ----------------------------------------------------------- accounts ----

type Account struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	Sector          *string  `json:"sector"`
	YearEstablished *int     `json:"year_established"`
	RevenueMUSD     *float64 `json:"revenue_musd,omitempty"` // omitted unless caller has revenue:read
	Employees       *int     `json:"employees"`
	OfficeLocation  *string  `json:"office_location"`
	SubsidiaryOf    *string  `json:"subsidiary_of"`
}

const accountCols = `id, name, sector, year_established, revenue_musd::float8, employees, office_location, subsidiary_of`

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	rows, err := s.db.Query(r.Context(),
		`SELECT `+accountCols+` FROM accounts
		 WHERE ($1 = '' OR name ILIKE '%' || $1 || '%') ORDER BY name LIMIT $2`,
		r.URL.Query().Get("q"), intParam(r, "limit", 25, 1, 100)) // values are bound parameters => no SQL injection
	if err != nil {
		serverErr(w, err)
		return
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Name, &a.Sector, &a.YearEstablished, &a.RevenueMUSD, &a.Employees, &a.OfficeLocation, &a.SubsidiaryOf); err != nil {
			serverErr(w, err)
			return
		}
		if !hasPerm(p.Role, "revenue:read") {
			a.RevenueMUSD = nil // field-level privacy control
		}
		out = append(out, a)
	}
	writeJSON(w, 200, map[string]any{"accounts": out})
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	var a Account
	err = s.db.QueryRow(r.Context(), `SELECT `+accountCols+` FROM accounts WHERE id=$1`, id).
		Scan(&a.ID, &a.Name, &a.Sector, &a.YearEstablished, &a.RevenueMUSD, &a.Employees, &a.OfficeLocation, &a.SubsidiaryOf)
	if err != nil {
		writeErr(w, 404, "account not found")
		return
	}
	if !hasPerm(principalFrom(r).Role, "revenue:read") {
		a.RevenueMUSD = nil
	}
	writeJSON(w, 200, a)
}

// ------------------------------------------------------- opportunities ----

type Opportunity struct {
	ID         string   `json:"id"`
	Agent      string   `json:"agent"`
	Product    string   `json:"product"`
	Account    *string  `json:"account"`
	Stage      string   `json:"stage"`
	EngageDate *string  `json:"engage_date"`
	CloseDate  *string  `json:"close_date"`
	CloseValue *float64 `json:"close_value,omitempty"` // omitted unless caller has deal_value:read
}

func (s *Server) listOpportunities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if st := q.Get("stage"); st != "" && !validStages[st] {
		writeErr(w, 400, "invalid stage")
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT o.id, o.agent, o.product, a.name, o.stage,
		       to_char(o.engage_date,'YYYY-MM-DD'), to_char(o.close_date,'YYYY-MM-DD'), o.close_value::float8
		FROM opportunities o LEFT JOIN accounts a ON a.id = o.account_id
		WHERE ($1 = '' OR o.stage = $1) AND ($2 = '' OR o.agent = $2)
		ORDER BY o.engage_date DESC NULLS LAST, o.id LIMIT $3`,
		q.Get("stage"), q.Get("agent"), intParam(r, "limit", 25, 1, 100))
	if err != nil {
		serverErr(w, err)
		return
	}
	defer rows.Close()
	canSeeValue := hasPerm(principalFrom(r).Role, "deal_value:read")
	out := []Opportunity{}
	for rows.Next() {
		var o Opportunity
		if err := rows.Scan(&o.ID, &o.Agent, &o.Product, &o.Account, &o.Stage, &o.EngageDate, &o.CloseDate, &o.CloseValue); err != nil {
			serverErr(w, err)
			return
		}
		if !canSeeValue {
			o.CloseValue = nil
		}
		out = append(out, o)
	}
	writeJSON(w, 200, map[string]any{"opportunities": out})
}

func (s *Server) createOpportunity(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Agent     string `json:"agent"`
		Product   string `json:"product"`
		AccountID *int64 `json:"account_id"`
		Stage     string `json:"stage"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Stage == "" {
		in.Stage = "Prospecting"
	}
	if !validStages[in.Stage] || in.Agent == "" || in.Product == "" {
		writeErr(w, 400, "agent, product and a valid stage are required")
		return
	}
	id := "OPP-" + randHex(4)
	_, err := s.db.Exec(r.Context(), `
		INSERT INTO opportunities (id, agent, product, account_id, stage, engage_date)
		VALUES ($1,$2,$3,$4,$5,CURRENT_DATE)`, id, in.Agent, in.Product, in.AccountID, in.Stage)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign key violation
		writeErr(w, 422, "unknown agent, product or account")
		return
	} else if err != nil {
		serverErr(w, err)
		return
	}
	auditFrom(r).Detail = map[string]any{"opportunity_id": id, "action": "create"}
	writeJSON(w, 201, map[string]string{"id": id})
}

func (s *Server) updateStage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Stage      string   `json:"stage"`
		CloseValue *float64 `json:"close_value"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validStages[in.Stage] {
		writeErr(w, 400, "invalid stage")
		return
	}
	// close_value is money: changing it additionally requires deal_value:read.
	if in.CloseValue != nil && !hasPerm(principalFrom(r).Role, "deal_value:read") {
		writeErr(w, 403, "forbidden: close_value requires deal_value:read")
		return
	}
	tag, err := s.db.Exec(r.Context(), `
		UPDATE opportunities
		SET stage = $2::text,
		    close_value = COALESCE($3::numeric, close_value),
		    close_date  = CASE WHEN $2::text IN ('Won','Lost') THEN CURRENT_DATE ELSE close_date END,
		    updated_at  = now()
		WHERE id = $1`, id, in.Stage, in.CloseValue)
	if err != nil {
		serverErr(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, 404, "opportunity not found")
		return
	}
	auditFrom(r).Detail = map[string]any{"opportunity_id": id, "action": "stage_change", "new_stage": in.Stage}
	if in.Stage == "Won" {
		s.notifyWon(id) // third-party integration (Slack-compatible webhook)
	}
	writeJSON(w, 200, map[string]string{"id": id, "stage": in.Stage})
}

// notifyWon posts to an optional webhook. Runs in the background with a hard
// timeout so a slow third party can never slow down or break our API.
func (s *Server) notifyWon(id string) {
	if s.cfg.SlackWebhook == "" {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]string{"text": fmt.Sprintf("Deal %s was marked Won", id)})
		c := http.Client{Timeout: 5 * time.Second}
		resp, err := c.Post(s.cfg.SlackWebhook, "application/json", bytes.NewReader(body))
		if err != nil {
			slog.Warn("webhook failed", "err", err)
			return
		}
		resp.Body.Close()
	}()
}

// ----------------------------------------------------------- analytics ----

func (s *Server) pipeline(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(),
		`SELECT stage, count(*), COALESCE(sum(close_value),0)::float8 FROM opportunities GROUP BY stage ORDER BY stage`)
	if err != nil {
		serverErr(w, err)
		return
	}
	defer rows.Close()
	canSeeValue := hasPerm(principalFrom(r).Role, "deal_value:read")
	type row struct {
		Stage      string   `json:"stage"`
		Count      int      `json:"count"`
		TotalValue *float64 `json:"total_value,omitempty"`
	}
	out := []row{}
	won, lost := 0, 0
	for rows.Next() {
		var x row
		var total float64
		if err := rows.Scan(&x.Stage, &x.Count, &total); err != nil {
			serverErr(w, err)
			return
		}
		if canSeeValue {
			x.TotalValue = &total
		}
		switch x.Stage {
		case "Won":
			won = x.Count
		case "Lost":
			lost = x.Count
		}
		out = append(out, x)
	}
	winRate := 0.0
	if won+lost > 0 {
		winRate = float64(won) / float64(won+lost)
	}
	writeJSON(w, 200, map[string]any{"stages": out, "win_rate": winRate})
}

// --------------------------------------------------------------- audit ----

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT id, ts, COALESCE(request_id,''), COALESCE(email,''), COALESCE(role,''), method, path, status, COALESCE(ip,''), detail
		FROM audit_log WHERE ($1 = '' OR email = $1) ORDER BY id DESC LIMIT $2`,
		r.URL.Query().Get("email"), intParam(r, "limit", 50, 1, 500))
	if err != nil {
		serverErr(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var ts time.Time
		var reqID, email, role, method, path, ip string
		var status int
		var detail map[string]any
		if err := rows.Scan(&id, &ts, &reqID, &email, &role, &method, &path, &status, &ip, &detail); err != nil {
			serverErr(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "ts": ts, "request_id": reqID, "email": email, "role": role,
			"method": method, "path": path, "status": status, "ip": ip, "detail": detail})
	}
	writeJSON(w, 200, map[string]any{"entries": out})
}

// ------------------------------------------------------------- helpers ----

func intParam(r *http.Request, name string, def, min, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return min2max(v, min, max)
}

func min2max(v, lo, hi int) int { return max(lo, min(v, hi)) }

// serverErr logs the real error but returns a generic message (no info leaks).
func serverErr(w http.ResponseWriter, err error) {
	slog.Error("request failed", "err", err)
	writeErr(w, 500, "internal error")
}
