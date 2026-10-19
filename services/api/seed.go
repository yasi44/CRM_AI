package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// readCSV returns each row as header->value. Uses only the standard library.
func readCSV(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(recs) < 1 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	var rows []map[string]string
	for _, rec := range recs[1:] {
		m := map[string]string{}
		for i, h := range recs[0] {
			if i < len(rec) {
				m[strings.TrimSpace(h)] = strings.TrimSpace(rec[i])
			}
		}
		rows = append(rows, m)
	}
	return rows, nil
}

// seed loads the 4 CSV files of the "CRM Sales Opportunities" dataset
// (Maven Analytics). Re-running is safe: every statement is an upsert.
// All values are passed as text and converted in SQL with NULLIF(...)::type,
// which turns empty CSV cells into proper NULLs.
func seed(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	load := func(file string) ([]map[string]string, error) { return readCSV(filepath.Join(cfg.DataDir, file)) }

	accts, err := load("accounts.csv")
	if err != nil {
		return err
	}
	for _, a := range accts {
		_, err = tx.Exec(ctx, `INSERT INTO accounts (name,sector,year_established,revenue_musd,employees,office_location,subsidiary_of)
			VALUES ($1, NULLIF($2,''), NULLIF($3,'')::int, NULLIF($4,'')::numeric, NULLIF($5,'')::int, NULLIF($6,''), NULLIF($7,''))
			ON CONFLICT (name) DO UPDATE SET sector=EXCLUDED.sector, year_established=EXCLUDED.year_established,
			  revenue_musd=EXCLUDED.revenue_musd, employees=EXCLUDED.employees,
			  office_location=EXCLUDED.office_location, subsidiary_of=EXCLUDED.subsidiary_of`,
			a["account"], a["sector"], a["year_established"], a["revenue"], a["employees"], a["office_location"], a["subsidiary_of"])
		if err != nil {
			return err
		}
	}
	prods, err := load("products.csv")
	if err != nil {
		return err
	}
	for _, p := range prods {
		if _, err = tx.Exec(ctx, `INSERT INTO products (name,series,sales_price) VALUES ($1, NULLIF($2,''), NULLIF($3,'')::numeric)
			ON CONFLICT (name) DO UPDATE SET series=EXCLUDED.series, sales_price=EXCLUDED.sales_price`,
			p["product"], p["series"], p["sales_price"]); err != nil {
			return err
		}
	}
	teams, err := load("sales_teams.csv")
	if err != nil {
		return err
	}
	for _, t := range teams {
		if _, err = tx.Exec(ctx, `INSERT INTO sales_agents (name,manager,regional_office) VALUES ($1, NULLIF($2,''), NULLIF($3,''))
			ON CONFLICT (name) DO UPDATE SET manager=EXCLUDED.manager, regional_office=EXCLUDED.regional_office`,
			t["sales_agent"], t["manager"], t["regional_office"]); err != nil {
			return err
		}
	}
	opps, err := load("sales_pipeline.csv")
	if err != nil {
		return err
	}
	for _, o := range opps {
		// Real-world data is messy (e.g. the original dataset spells one product
		// "GTXPro" in the pipeline but "GTX Pro" in the product list). Instead of
		// crashing, create a placeholder product/agent so the row still loads.
		_, _ = tx.Exec(ctx, `INSERT INTO products (name) VALUES ($1) ON CONFLICT DO NOTHING`, o["product"])
		_, _ = tx.Exec(ctx, `INSERT INTO sales_agents (name) VALUES ($1) ON CONFLICT DO NOTHING`, o["sales_agent"])
		if _, err = tx.Exec(ctx, `INSERT INTO opportunities (id,agent,product,account_id,stage,engage_date,close_date,close_value)
			VALUES ($1,$2,$3,(SELECT id FROM accounts WHERE name=$4),$5,NULLIF($6,'')::date,NULLIF($7,'')::date,NULLIF($8,'')::numeric)
			ON CONFLICT (id) DO UPDATE SET stage=EXCLUDED.stage, close_date=EXCLUDED.close_date, close_value=EXCLUDED.close_value`,
			o["opportunity_id"], o["sales_agent"], o["product"], o["account"], o["deal_stage"],
			o["engage_date"], o["close_date"], o["close_value"]); err != nil {
			return fmt.Errorf("opportunity %s: %w", o["opportunity_id"], err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	slog.Info("seeded", "accounts", len(accts), "products", len(prods), "agents", len(teams), "opportunities", len(opps))

	// Demo users are OPT-IN. Never ship default passwords to production.
	if os.Getenv("SEED_DEMO_USERS") == "true" {
		pw := os.Getenv("DEMO_PASSWORD")
		for _, u := range []struct{ email, role string }{
			{"viewer@demo.local", "viewer"}, {"rep@demo.local", "rep"},
			{"manager@demo.local", "manager"}, {"admin@demo.local", "admin"},
		} {
			if err := createUser(ctx, pool, u.email, pw, u.role); err != nil {
				return err
			}
		}
	}
	return nil
}

func createUser(ctx context.Context, pool *pgxpool.Pool, email, password, role string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if _, ok := rolePerms[role]; !ok {
		return fmt.Errorf("unknown role %q", role)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)
		ON CONFLICT (email) DO UPDATE SET password_hash=EXCLUDED.password_hash, role=EXCLUDED.role`,
		strings.ToLower(email), string(hash), role)
	if err == nil {
		slog.Info("user ready", "email", email, "role", role)
	}
	return err
}
