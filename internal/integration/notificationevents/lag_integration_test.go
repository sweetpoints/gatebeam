//go:build integration

package notificationevents_test

import (
	"fmt"
	"gatebeam/internal/modules/notification/application/alerts"
	notifications "gatebeam/internal/modules/notification/infrastructure/postgres"
	"gatebeam/internal/modules/observability/application/ingest"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"gatebeam/internal/modules/observability/infrastructure/parquet"
	observations "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionIngestionUnknownLagPreservesFailureUntilObservedRecovery(t *testing.T) {
	for _, recovery := range []string{"drained", "fresh_with_backlog"} {
		t.Run(recovery, func(t *testing.T) {
			p := testkit.Postgres(t)
			tx := postgres.NewRunner(p)
			sourceStore := observations.New()
			sink := notifications.New()
			consumer := alerts.New(tx, sink, sink)
			valid := func(at time.Time) string {
				return fmt.Sprintf(`{"schema_version":1,"site_id":"11111111-1111-4111-8111-111111111111","request_id":"0123456789abcdef0123456789abcdef","time":%q,"route":"0","method":"GET","status":200,"bytes_sent":20,"request_time":"0.012"}`+"\n", at.UTC().Format(time.RFC3339Nano))
			}
			// The real logfile adapter stops the first batch at its 1024-row limit.
			// Its next 1-MiB read contains only rejected rows, with additional bytes still unread.
			old := strings.Repeat(valid(time.Now().Add(-2*time.Minute)), 1024)
			invalid := strings.Repeat("!\n", (1<<20)/2)
			tail := "!\n" // Draining even malformed-only bytes establishes zero backlog.
			if recovery == "fresh_with_backlog" {
				tail = strings.Repeat(valid(time.Now()), 1025)
			}
			input := old + invalid + tail
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "access.log"), []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			source, err := logfile.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			spool, err := parquet.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			producer := ingest.New(tx, sourceStore, source, spool)
			segments, err := source.Discover(t.Context())
			if err != nil || len(segments) != 1 {
				t.Fatal(segments, err)
			}
			segment := segments[0]
			assertLag := func(want string, events int) {
				t.Helper()
				if err := consumer.Consume(t.Context()); err != nil {
					t.Fatal(err)
				}
				var state string
				var count int
				if err := p.QueryRow(t.Context(), `SELECT state FROM notification_incidents WHERE event->>'kind'='ingestion_lag'`).Scan(&state); err != nil || state != want {
					t.Fatal("incorrect derived lag state", state, want, err)
				}
				if err := p.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE event_type='IngestionLagChanged'`).Scan(&count); err != nil || count != events {
					t.Fatal("unexpected lag transition", count, events, err)
				}
			}
			first, err := producer.Ingest(t.Context(), segment)
			if err != nil {
				t.Fatal(err)
			}
			if !first.LagKnown || first.LagSeconds < 120 || first.End >= segment.Size {
				t.Fatal("fixture did not produce observed stale backlog", first.LagSeconds)
			}
			assertLag("firing", 1)
			unknown, err := producer.Ingest(t.Context(), segment)
			if err != nil {
				t.Fatal(err)
			}
			if unknown.LagKnown || unknown.Invalid == 0 || len(unknown.Buckets) != 0 || unknown.End >= segment.Size {
				t.Fatal("fixture did not produce malformed-only backlog")
			}
			assertLag("firing", 1)
			var rejected string
			if err = p.QueryRow(t.Context(), `SELECT state FROM observability_alert_outcomes WHERE kind='LogRecordsChanged'`).Scan(&rejected); err != nil || rejected != "firing" {
				t.Fatal("bad-row alert lost", rejected, err)
			}
			final, err := producer.Ingest(t.Context(), segment)
			if err != nil {
				t.Fatal(err)
			}
			if !final.LagKnown || recovery == "drained" && final.End != segment.Size || recovery == "fresh_with_backlog" && final.End >= segment.Size {
				t.Fatal("incorrect recovery evidence")
			}
			assertLag("resolved", 2)
			if err = tx.Within(t.Context(), func(sc transaction.Scope) error { return sourceStore.CommitWithin(sc, segment, unknown) }); err != nil {
				t.Fatal(err)
			}
			assertLag("resolved", 2)
		})
	}
}
