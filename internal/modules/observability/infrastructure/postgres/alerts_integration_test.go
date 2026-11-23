//go:build integration

package postgres_test

import (
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"strings"
	"testing"
	"time"
)

func TestOldManifestReplayCannotResolveLaterPipelineFailure(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	segment := domain.Segment{ID: strings.Repeat("c", 64), Path: "access.log", Fingerprint: "owned", Size: 1}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if _, e := r.CursorWithin(sc, segment); e != nil {
			return e
		}
		return r.CommitWithin(sc, segment, domain.Batch{ID: "batch", SegmentID: segment.ID, SourceChecksum: "owned", Start: 0, End: 1})
	}); e != nil {
		t.Fatal(e)
	}
	commit := func() {
		t.Helper()
		if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.CommitManifestWithin(sc, domain.Manifest{BatchID: "batch"}) }); e != nil {
			t.Fatal(e)
		}
	}
	commit()
	if e := r.Failure(t.Context(), p, "archive_unavailable", time.Now()); e != nil {
		t.Fatal(e)
	}
	commit()
	var state string
	if e := p.QueryRow(t.Context(), `SELECT state FROM observability_alert_outcomes WHERE kind='ArchivePipelineChanged'`).Scan(&state); e != nil || state != "firing" {
		t.Fatal("replayed old archive cleared current failure", state, e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.CleanedWithin(sc, "batch") }); e != nil {
		t.Fatal(e)
	}
	if e := p.QueryRow(t.Context(), `SELECT state FROM observability_alert_outcomes WHERE kind='ArchivePipelineChanged'`).Scan(&state); e != nil || state != "resolved" {
		t.Fatal("completed archive did not recover", state, e)
	}
	if e := r.Failure(t.Context(), p, "archive_unavailable", time.Now().Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.CleanedWithin(sc, "batch") }); e != nil {
		t.Fatal(e)
	}
	if e := p.QueryRow(t.Context(), `SELECT state FROM observability_alert_outcomes WHERE kind='ArchivePipelineChanged'`).Scan(&state); e != nil || state != "firing" {
		t.Fatal("duplicate cleanup cleared newer failure", state, e)
	}
}
