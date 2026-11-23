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
	pq "github.com/parquet-go/parquet-go"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotationAndSecretRedaction(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(p)
	r := repo.New()
	logs := t.TempDir()
	spoolDir := t.TempDir()
	path := filepath.Join(logs, "access.log")
	first := strings.Replace(line, `"cookie":"SECRET"`, `"cookie":"SECRET","authorization":"Bearer SECRET","body":"4111111111111111","signature":"SECRET"`, 1)
	// A partial record must stay unread until completed, even across rename.
	cut := len(first) / 2
	if e := os.WriteFile(path, []byte(first+first[:cut]), 0600); e != nil {
		t.Fatal(e)
	}
	source, _ := logfile.Open(logs)
	defer source.Close()
	w, _ := spool.New(spoolDir)
	collector := ingest.New(tx, r, source, w)
	segments, e := source.Discover(ctx)
	if e != nil {
		t.Fatal(e)
	}
	b, e := collector.Ingest(ctx, segments[0])
	if e != nil || b.End != int64(len(first)) {
		t.Fatal(b, e)
	}
	rotated := "access.20261107T000000.000000001.log"
	if e = os.Rename(path, filepath.Join(logs, rotated)); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(filepath.Join(logs, rotated), os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString(first[cut:] + "{bad SECRET 4111111111111111}\n" + strings.Replace(first, `"schema_version":1`, `"schema_version":999`, 1))
	f.Sync()
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(first), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(logs, rotated+".closed"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	segments, e = source.Discover(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, seg := range segments {
		if _, e = collector.Ingest(ctx, seg); e != nil {
			t.Fatal(e)
		}
	}
	var count, invalid, schema, events int64
	if e = p.QueryRow(ctx, "SELECT sum(requests) FROM observability_stats").Scan(&count); e != nil || count != 3 {
		t.Fatal("unread rotation lost", count, e)
	}
	if e = p.QueryRow(ctx, "SELECT sum(invalid_count),sum(schema_count) FROM observability_batches").Scan(&invalid, &schema); e != nil || invalid != 1 || schema != 1 {
		t.Fatal(invalid, schema, e)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE event_type='LogRecordsRejected'").Scan(&events); e != nil || events != 1 {
		t.Fatal(events, e)
	}
	rows := 0
	err := filepath.WalkDir(spoolDir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !strings.HasSuffix(path, ".parquet") {
			return nil
		}
		records, e := pq.ReadFile[spool.Row](path)
		if e != nil {
			return e
		}
		rows += len(records)
		for _, r := range records {
			if strings.Contains(r.PathPattern, "SECRET") {
				t.Fatal("secret escaped whitelist")
			}
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		for _, secret := range []string{"SECRET", "4111111111111111", "authorization", "cookie"} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("persistent secret %s", secret)
			}
		}
		return nil
	})
	if err != nil || rows != 3 {
		t.Fatal(rows, err)
	}
	var payload string
	if e = p.QueryRow(ctx, "SELECT payload::text FROM outbox WHERE event_type='LogRecordsRejected'").Scan(&payload); e != nil || strings.Contains(payload, "SECRET") {
		t.Fatal("unsafe rejection event", e)
	}
	// Copytruncate/shortening is fail closed: never reset the stored watermark.
	if e = os.Truncate(path, 0); e != nil {
		t.Fatal(e)
	}
	segments, e = source.Discover(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, seg := range segments {
		if seg.Path == "access.log" {
			if _, e = collector.Ingest(ctx, seg); !errors.Is(e, domain.ErrSourceChanged) {
				t.Fatal("truncation accepted", e)
			}
		}
	}
}
func TestOversizeIsBoundedAndRejectedOnce(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	logs := t.TempDir()
	data := line + strings.Repeat("X", 2*domain.MaxRead) + "\n" + line
	os.WriteFile(filepath.Join(logs, "access.log"), []byte(data), 0600)
	source, _ := logfile.Open(logs)
	defer source.Close()
	w, _ := spool.New(t.TempDir())
	collector := ingest.New(postgres.NewRunner(p), repo.New(), source, w)
	segs, _ := source.Discover(ctx)
	for range 5 {
		b, e := collector.Ingest(ctx, segs[0])
		if e != nil || b.End-b.Start > domain.MaxRead {
			t.Fatal(b, e)
		}
	}
	var oversize, count int64
	if e := p.QueryRow(ctx, "SELECT sum(oversize_count) FROM observability_batches").Scan(&oversize); e != nil || oversize != 1 {
		t.Fatal(oversize, e)
	}
	if e := p.QueryRow(ctx, "SELECT sum(requests) FROM observability_stats").Scan(&count); e != nil || count != 2 {
		t.Fatal(count, e)
	}
}

type reject struct{}

func (reject) RequireWithin(transaction.Scope, stats.ActorRef, []string) error {
	return stats.ErrDenied
}
func TestStatisticsScopeAndMergedLatency(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	ctx := context.Background()
	logs := t.TempDir()
	fast := strings.Replace(line, `"route":"0"`, `"route":"0","config_id":"`+strings.Repeat("a", 64)+`","path_pattern":"/old"`, 1)
	slow := strings.Replace(strings.Replace(strings.Replace(fast, `"0.012"`, `"5.000"`, 1), strings.Repeat("a", 64), strings.Repeat("b", 64), 1), `"/old"`, `"/new"`, 1)
	os.WriteFile(filepath.Join(logs, "access.log"), []byte(strings.Repeat(fast, 100)+slow), 0600)
	source, _ := logfile.Open(logs)
	defer source.Close()
	w, _ := spool.New(t.TempDir())
	collector := ingest.New(tx, r, source, w)
	segs, _ := source.Discover(ctx)
	if _, e := collector.Ingest(ctx, segs[0]); e != nil {
		t.Fatal(e)
	}
	from := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	f := stats.Filter{SiteIDs: []string{site}, From: from, To: from.Add(time.Hour)}
	result, e := stats.New(tx, allow{}, r).Query(ctx, stats.ActorRef{}, f)
	if e != nil || result.Count != 101 || result.P95Micros != 25000 || result.Micros != 6200000 || len(result.Buckets) != 2 {
		t.Fatal(result, e)
	}
	f.ConfigID = strings.Repeat("a", 64)
	selected, e := stats.New(tx, allow{}, r).Query(ctx, stats.ActorRef{}, f)
	if e != nil || selected.Count != 100 || len(selected.Buckets) != 1 || selected.P95Micros != 25000 {
		t.Fatal("configuration filter lost fixed route identity", selected, e)
	}
	f.ConfigID = ""
	if _, e = stats.New(tx, reject{}, r).Query(ctx, stats.ActorRef{}, f); !errors.Is(e, stats.ErrDenied) {
		t.Fatal("scope bypass", e)
	}
	f.To = f.From.Add(25 * time.Hour)
	if _, e = stats.New(tx, allow{}, r).Query(ctx, stats.ActorRef{}, f); !errors.Is(e, domain.ErrInvalid) {
		t.Fatal("unbounded query", e)
	}
}
func TestBatchStatsCursorAndOutboxRollbackTogether(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(p)
	r := repo.New()
	logs := t.TempDir()
	os.WriteFile(filepath.Join(logs, "access.log"), []byte(line+"invalid\n"), 0600)
	source, _ := logfile.Open(logs)
	defer source.Close()
	w, _ := spool.New(t.TempDir())
	collector := ingest.New(tx, r, source, w)
	segs, _ := source.Discover(ctx)
	if _, e := p.Exec(ctx, `ALTER TABLE outbox ADD CONSTRAINT reject_logs CHECK(event_type <> 'LogRecordsRejected')`); e != nil {
		t.Fatal(e)
	}
	if _, e := collector.Ingest(ctx, segs[0]); e == nil {
		t.Fatal("outbox failure ignored")
	}
	var batches, statsCount, offset int
	if e := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM observability_batches),(SELECT count(*) FROM observability_stats),(SELECT source_offset FROM observability_segments LIMIT 1)`).Scan(&batches, &statsCount, &offset); e != nil || batches != 0 || statsCount != 0 || offset != 0 {
		t.Fatal(batches, statsCount, offset, e)
	}
}

func TestSpoolCapacityFailureLeavesCursorUnadvanced(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	logs := t.TempDir()
	os.WriteFile(filepath.Join(logs, "access.log"), []byte(line), 0600)
	source, _ := logfile.Open(logs)
	defer source.Close()
	w, _ := spool.New(t.TempDir())
	w.MaxBytes = 1
	collector := ingest.New(postgres.NewRunner(p), repo.New(), source, w)
	segs, _ := source.Discover(ctx)
	if _, e := collector.Ingest(ctx, segs[0]); !errors.Is(e, domain.ErrCapacity) {
		t.Fatal("spool refusal missing", e)
	}
	var offset, batches int
	if e := p.QueryRow(ctx, `SELECT (SELECT source_offset FROM observability_segments LIMIT 1),(SELECT count(*) FROM observability_batches)`).Scan(&offset, &batches); e != nil || offset != 0 || batches != 0 {
		t.Fatal("watermark advanced before durable spool", offset, batches, e)
	}
}
