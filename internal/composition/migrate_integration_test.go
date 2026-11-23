//go:build integration

package composition

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMigrateEmbeddedRuntime(t *testing.T) {
	dsn := os.Getenv("GATEBEAM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("run scripts/check-db.sh: PostgreSQL DSN required")
	}
	path := filepath.Join(t.TempDir(), "database")
	if e := os.WriteFile(path, []byte(dsn), 0600); e != nil {
		t.Fatal(e)
	}
	// This outer fixture budget covers two migration passes and the final
	// idempotency read. Each Run still enforces its production sixty-second cap.
	fixtureBudget := 15 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		fixtureBudget *= 12
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), fixtureBudget)
	defer cancel()
	cfg := bootstrap.Config{Mode: "migrate", DatabaseFile: path}
	for pass := range 2 {
		if e := Run(ctx, "migrate", cfg); e != nil {
			t.Fatalf("embedded migration pass=%d elapsed=%s fixture_budget=%s fixture_context=%v: %v", pass+1, time.Since(started), fixtureBudget, ctx.Err(), e)
		}
	}
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal("test pool unavailable")
	}
	defer p.Close()
	var n int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM goose_db_version WHERE version_id=1 AND is_applied").Scan(&n); e != nil || n != 1 {
		t.Fatalf("migration version %d: %v", n, e)
	}
}
