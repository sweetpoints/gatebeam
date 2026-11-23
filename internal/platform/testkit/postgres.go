// Package testkit supplies mandatory real PostgreSQL fixtures; missing DB is fatal.
package testkit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"gatebeam/db/migrations"
	"gatebeam/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"os"
	"testing"
	"time"
)

func Postgres(t testing.TB) *pgxpool.Pool { return postgresAt(t, 0) }

// PostgresAt starts an owned fixture at a real historical schema version. It
// does not delete migration history or mutate a shared/production database.
func PostgresAt(t testing.TB, version int64) *pgxpool.Pool {
	if version < 1 {
		t.Fatal("positive fixture schema version required")
	}
	return postgresAt(t, version)
}
func postgresAt(t testing.TB, version int64) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("GATEBEAM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("run scripts/check-db.sh: PostgreSQL DSN required")
	}
	// Fixture setup and teardown are CI infrastructure budgets. Product operation
	// deadlines and capacity scenario watchdogs are independent of this profile.
	fixtureFactor := time.Duration(1)
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		fixtureFactor = 12
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureFactor*15*time.Second)
	defer cancel()
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal("invalid test DSN")
	}
	// Each fixture owns an isolated schema, so -p 2 packages cannot truncate
	// one another's jobs/audit/authentication data. Names are generated locally.
	var nonce [12]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		t.Fatal("fixture name generation failed")
	}
	schema := "test_" + hex.EncodeToString(nonce[:])
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("fixture database unavailable")
	}
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); e != nil {
		admin.Close(ctx)
		t.Fatal("fixture schema unavailable")
	}
	admin.Close(ctx)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), fixtureFactor*5*time.Second)
		defer cancel()
		admin, e := pgx.Connect(c, dsn)
		if e != nil {
			t.Error("fixture cleanup database unavailable")
			return
		}
		defer admin.Close(c)
		if _, e = admin.Exec(c, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); e != nil {
			code := ""
			var pgError *pgconn.PgError
			if errors.As(e, &pgError) {
				code = pgError.Code
			}
			// Report only error classification, never DSNs or SQL error payloads.
			t.Errorf("fixture cleanup failed: deadline_expired=%t sqlstate=%s", c.Err() != nil, code)
		}
	})
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 8
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal("test database unavailable")
	}
	t.Cleanup(p.Close)
	if version == 0 {
		e = postgres.Migrate(ctx, p)
	} else {
		db := stdlib.OpenDBFromPool(p)
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files, goose.WithDisableGlobalRegistry(true))
		if err == nil {
			_, err = provider.UpTo(ctx, version)
		}
		_ = db.Close()
		e = err
	}
	if e != nil {
		t.Fatal(e)
	}
	var serverVersion int
	if e = p.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&serverVersion); e != nil || serverVersion < 180000 || serverVersion >= 190000 {
		t.Fatal("PostgreSQL 18 required")
	}
	return p
}
