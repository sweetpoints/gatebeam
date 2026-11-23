//go:build integration

package composition

import (
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetirementFinalizeFailureReportsFixedReasonAndRecovers(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	dir := t.TempDir()
	name := "access.20261107T120000.000000000.log"
	seg := domain.Segment{ID: strings.Repeat("f", 64), Path: name, Closed: true}
	if e := os.WriteFile(filepath.Join(dir, name+".closed"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.BeginRetirement(sc, seg) }); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(t.Context(), `CREATE FUNCTION fail_retirement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.retired THEN RAISE EXCEPTION 'SECRET/path/token'; END IF; RETURN NEW; END $$; CREATE TRIGGER retirement_failure BEFORE UPDATE ON observability_segments FOR EACH ROW EXECUTE FUNCTION fail_retirement()`); e != nil {
		t.Fatal(e)
	}
	open := func() (retirementSource, error) { return logfile.Open(dir) }
	e := retireSources(t.Context(), tx, r, open)
	if e == nil {
		t.Fatal("finalize failure swallowed")
	}
	var retired bool
	if err := p.QueryRow(t.Context(), `SELECT retired FROM observability_segments WHERE physical_id=$1`, seg.ID).Scan(&retired); err != nil || retired {
		t.Fatal("failed finalization lost intent", retired, err)
	}
	if _, err := os.Stat(filepath.Join(dir, name+".closed")); !os.IsNotExist(err) {
		t.Fatal("missing-source marker recovery failed", err)
	}
	// Same fixed-code path used by runArchiveWorker; neither its diagnostic nor
	// its durable receipt may include the raw failing PostgreSQL message.
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prior := os.Stderr
	os.Stderr = write
	var last time.Time
	func() {
		defer func() { os.Stderr = prior; write.Close() }()
		historyFailure(t.Context(), p, "archive_unavailable", &last)
		historyFailure(t.Context(), p, "archive_unavailable", &last)
	}()
	output, err := io.ReadAll(read)
	read.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(output), "\n") != 1 || !strings.Contains(string(output), `"reason":"archive_unavailable"`) || strings.Contains(string(output), "SECRET") {
		t.Fatal("unsafe or unbounded diagnostic", string(output))
	}
	var count int
	var payload string
	if err = p.QueryRow(t.Context(), `SELECT count(*),coalesce(max(payload::text),'') FROM outbox WHERE event_type='LogIngestFailed'`).Scan(&count, &payload); err != nil || count != 1 || strings.Contains(payload, "SECRET") {
		t.Fatal("failure receipt", count, payload, err)
	}
	if _, e = p.Exec(t.Context(), `DROP TRIGGER retirement_failure ON observability_segments`); e != nil {
		t.Fatal(e)
	}
	if e = retireSources(t.Context(), tx, r, open); e != nil {
		t.Fatal("crash retry failed", e)
	}
	if e = p.QueryRow(t.Context(), `SELECT retired FROM observability_segments WHERE physical_id=$1`, seg.ID).Scan(&retired); e != nil || !retired {
		t.Fatal("recovered intent not finalized", retired, e)
	}
}
