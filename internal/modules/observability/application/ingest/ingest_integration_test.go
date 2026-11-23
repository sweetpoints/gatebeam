//go:build integration

package ingest_test

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/application/ingest"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	spool "gatebeam/internal/modules/observability/infrastructure/parquet"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const site = "11111111-1111-4111-8111-111111111111"
const line = `{"schema_version":1,"site_id":"11111111-1111-4111-8111-111111111111","request_id":"0123456789abcdef0123456789abcdef","time":"2026-11-07T00:00:00Z","route":"0","method":"GET","status":200,"bytes_sent":20,"request_time":"0.012","path":"/SECRET?token=SECRET","cookie":"SECRET"}` + "\n"

type failCommit struct {
	ingest.Store
	fail bool
}

func (f *failCommit) CommitWithin(sc transaction.Scope, s domain.Segment, b domain.Batch) error {
	if f.fail {
		return errors.New("simulated crash after spool")
	}
	return f.Store.CommitWithin(sc, s, b)
}

type allow struct{}

func (allow) RequireWithin(transaction.Scope, stats.ActorRef, []string) error { return nil }
func TestCrashBetweenSpoolAndCursorDoesNotDoubleCount(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	f := &failCommit{r, true}
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "access.log"), []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	source, e := logfile.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	w, e := spool.New(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s := ingest.New(tx, f, source, w)
	ctx := context.Background()
	segments, e := source.Discover(ctx)
	if e != nil || len(segments) != 1 {
		t.Fatal(e, segments)
	}
	if _, e = s.Ingest(ctx, segments[0]); e == nil {
		t.Fatal("crash not injected")
	}
	var n int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM observability_batches").Scan(&n); e != nil || n != 0 {
		t.Fatal("failed commit retained batch", e, n)
	}
	f.fail = false
	b, e := s.Ingest(ctx, segments[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Within(ctx, func(sc transaction.Scope) error { return r.CommitWithin(sc, segments[0], b) }); e != nil {
		t.Fatal(e)
	}
	query := stats.New(tx, allow{}, r)
	from := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	result, e := query.Query(ctx, stats.ActorRef{}, stats.Filter{SiteIDs: []string{site}, From: from, To: from.Add(time.Hour)})
	if e != nil || result.Count != 1 {
		t.Fatalf("source range counted %d times; error %v", result.Count, e)
	}
}
