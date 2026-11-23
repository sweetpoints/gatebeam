//go:build integration

package composition

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/testkit"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogWorkerProducesStatsAndOnlyEnqueuesFixedRotation(t *testing.T) {
	p := testkit.Postgres(t)
	logs := t.TempDir()
	spool := t.TempDir()
	data := `{"schema_version":1,"site_id":"11111111-1111-4111-8111-111111111111","request_id":"0123456789abcdef0123456789abcdef","time":"2026-11-07T00:00:00Z","route":"-1","method":"GET","status":200,"bytes_sent":5,"request_time":"0.001"}` + "\n"
	if e := os.WriteFile(filepath.Join(logs, "access.log"), []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runLogWorker(ctx, bootstrap.Config{LogDirectory: logs, LogSpoolDirectory: spool}, p) }()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	found := false
	for !found {
		select {
		case <-deadline.C:
			t.Fatal("log worker did not ingest")
		case <-tick.C:
			var count, rotations int
			err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM observability_stats),(SELECT count(*) FROM jobs WHERE kind='deployment.rotate_logs' AND payload='{}'::jsonb AND status='pending')`).Scan(&count, &rotations)
			found = err == nil && count == 1 && rotations == 1
		}
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("worker cancellation blocked")
	}
}
