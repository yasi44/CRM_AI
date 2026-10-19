package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// ------------------------------------------------------------ helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// decode reads a JSON body safely: size-capped, unknown fields rejected.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, 400, "invalid JSON body")
		return false
	}
	return true
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------- request id ----

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", randHex(8)) // lets you correlate logs <-> audit rows
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// --------------------------------------------------------- audit log ----

// auditInfo is filled in LATER by login/protect (they know who the user is);
// the audit middleware reads it AFTER the handler finishes.
type auditInfo struct {
	UserID, Email, Role string
	Detail              map[string]any // extra business context (e.g. which opportunity changed)
}

type auditKey struct{}

func auditFrom(r *http.Request) *auditInfo {
	i, _ := r.Context().Value(auditKey{}).(*auditInfo)
	return i
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

func clientIP(r *http.Request) string {
	// NOTE: behind a load balancer use its trusted X-Forwarded-For handling instead.
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// audit records EVERY request (including failed logins and 401/403s) to an
// append-only table. Failed attempts are exactly what auditors want to see.
func (s *Server) audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		info := &auditInfo{}
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		r = r.WithContext(context.WithValue(r.Context(), auditKey{}, info))
		next.ServeHTTP(rec, r)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := s.db.Exec(ctx, `INSERT INTO audit_log
			(request_id, user_id, email, role, method, path, status, ip, detail)
			VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''), $5, $6, $7, $8, $9)`,
			w.Header().Get("X-Request-ID"), info.UserID, info.Email, info.Role,
			r.Method, r.URL.Path, rec.status, clientIP(r), info.Detail)
		if err != nil {
			// In regulated environments you may prefer to fail the request instead.
			slog.Error("audit write failed", "err", err)
		}
	})
}

// --------------------------------------------------------- rate limit ----

type bucket struct {
	count int
	reset time.Time
}

type limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*bucket
}

func newLimiter(limit int, window time.Duration) *limiter {
	return &limiter{limit: limit, window: window, hits: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 10000 { // opportunistic cleanup keeps memory bounded
		for k, b := range l.hits {
			if now.After(b.reset) {
				delete(l.hits, k)
			}
		}
	}
	b, ok := l.hits[key]
	if !ok || now.After(b.reset) {
		l.hits[key] = &bucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	b.count++
	return b.count <= l.limit
}

// In-memory per-IP limiter: fine for one replica. With many replicas, use a
// shared store (Redis) or enforce limits at the gateway / load balancer.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, 429, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
