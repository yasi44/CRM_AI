package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------- RBAC ----
// Roles map to PERMISSIONS, and handlers check permissions (not role names).
// That keeps handlers stable when you later add roles or change what a role can do.

func set(perms ...string) map[string]bool {
	m := map[string]bool{}
	for _, p := range perms {
		m[p] = true
	}
	return m
}

func merge(a map[string]bool, extra ...string) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for _, p := range extra {
		m[p] = true
	}
	return m
}

var (
	viewerPerms  = set("accounts:read", "opportunities:read", "analytics:read") // NO revenue / deal values (data privacy)
	repPerms     = merge(viewerPerms, "opportunities:write", "revenue:read", "deal_value:read")
	managerPerms = merge(repPerms, "audit:read")
	adminPerms   = merge(managerPerms, "users:manage")

	rolePerms = map[string]map[string]bool{
		"viewer": viewerPerms, "rep": repPerms, "manager": managerPerms, "admin": adminPerms,
	}
)

func hasPerm(role, perm string) bool { return rolePerms[role][perm] }

// -------------------------------------------------------------- tokens ----

type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

type Principal struct{ ID, Email, Role string }

type principalKey struct{}

func principalFrom(r *http.Request) Principal {
	p, _ := r.Context().Value(principalKey{}).(Principal)
	return p
}

func (s *Server) issueToken(id, email, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		Email: email, Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id,
			Issuer:    "crm-api", // validated on every request
			Audience:  jwt.ClaimStrings{"crm"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.TokenTTL)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.JWTSecret))
}

// dummyHash lets us spend the same bcrypt time for unknown emails, so response
// timing does not reveal which emails exist (user enumeration defence).
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	var id, hash, role string
	err := s.db.QueryRow(r.Context(),
		`SELECT id::text, password_hash, role FROM users WHERE email = $1`,
		strings.ToLower(strings.TrimSpace(in.Email))).Scan(&id, &hash, &role)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(in.Password))
		writeErr(w, 401, "invalid credentials")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		writeErr(w, 401, "invalid credentials") // same message for both failures
		return
	}
	tok, err := s.issueToken(id, in.Email, role)
	if err != nil {
		writeErr(w, 500, "could not issue token")
		return
	}
	if info := auditFrom(r); info != nil { // so the audit row shows who logged in
		info.UserID, info.Email, info.Role = id, in.Email, role
	}
	writeJSON(w, 200, map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int(s.cfg.TokenTTL.Seconds()),
	})
}

// protect = authentication + authorization for one route.
// perm == "" means "any authenticated user".
func (s *Server) protect(perm string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || raw == "" {
			writeErr(w, 401, "missing bearer token")
			return
		}
		claims := &Claims{}
		_, err := jwt.ParseWithClaims(raw, claims,
			func(*jwt.Token) (any, error) { return []byte(s.cfg.JWTSecret), nil },
			jwt.WithValidMethods([]string{"HS256"}), // blocks the classic "alg=none" attack
			jwt.WithIssuer("crm-api"), jwt.WithAudience("crm"), jwt.WithExpirationRequired())
		if err != nil {
			writeErr(w, 401, "invalid or expired token")
			return
		}
		p := Principal{ID: claims.Subject, Email: claims.Email, Role: claims.Role}
		if info := auditFrom(r); info != nil {
			info.UserID, info.Email, info.Role = p.ID, p.Email, p.Role
		}
		if perm != "" && !hasPerm(p.Role, perm) {
			writeErr(w, 403, "forbidden: requires "+perm) // authenticated, but not allowed
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}
