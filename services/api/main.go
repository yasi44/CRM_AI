// CRM API: the system of record. It is the ONLY component that touches the
// database, and the ONLY place where authorization (RBAC) is enforced.
// The MCP server and the AI agent are clients of this API, so an AI can never
// do more than the human user whose token it carries.
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

var _ embed.FS // keeps the embed import explicit

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	// Used by the Docker HEALTHCHECK (distroless images have no curl).
	if cmd == "healthcheck" {
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://127.0.0.1:8080/healthz")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}

	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fatal("db pool", err)
	}
	defer pool.Close()
	if err := migrate(ctx, pool); err != nil {
		fatal("migrate", err)
	}

	switch cmd {
	case "serve":
		serve(ctx, cfg, pool)
	case "migrate":
		slog.Info("migrations applied")
	case "seed":
		if err := seed(ctx, pool, cfg); err != nil {
			fatal("seed", err)
		}
	case "create-user": // crm-api create-user EMAIL PASSWORD ROLE
		if len(os.Args) != 5 {
			fatal("usage: create-user EMAIL PASSWORD ROLE", nil)
		}
		if err := createUser(ctx, pool, os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fatal("create-user", err)
		}
	default:
		fatal(fmt.Sprintf("unknown command %q", cmd), nil)
	}
}

// migrate applies schema.sql under a Postgres advisory lock so that several
// containers starting at once (api + seed) cannot race each other.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(727274)"); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(727274)")
	_, err = conn.Exec(ctx, schemaSQL)
	return err
}

func serve(ctx context.Context, cfg Config, pool *pgxpool.Pool) {
	s := &Server{cfg: cfg, db: pool, limiter: newLimiter(120, time.Minute)}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second, // mitigates slowloris
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { // graceful shutdown: finish in-flight requests on SIGTERM
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("api listening", "addr", cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("listen", err)
	}
}
