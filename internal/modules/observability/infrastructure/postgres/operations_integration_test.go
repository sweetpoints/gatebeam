//go:build integration

package postgres_test

import (
	"errors"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"strings"
	"testing"
	"time"
)

func TestLocalFrozenJobPinsCleanupAndCancelledLeaseCannotComplete(t *testing.T) {
	p := testkit.Postgres(t)
	r := repo.New()
	tx := postgres.NewRunner(p)
	ctx := t.Context()
	at := time.Now()
	site := "11111111-1111-4111-8111-111111111111"
	seg := domain.Segment{ID: strings.Repeat("a", 64), Fingerprint: "owned", Path: "access.log", Size: 1}
	object := domain.Object{SchemaVersion: 1, SiteID: site, Hour: at.UTC().Format("2006-01-02/15"), Key: site + "/" + at.UTC().Format("2006-01-02/15") + "/" + strings.Repeat("a", 64) + ".parquet", MinTime: at, MaxTime: at, Rows: 1, Bytes: 128, Checksum: strings.Repeat("a", 64)}
	b := domain.Batch{ID: "owned", SegmentID: seg.ID, Start: 0, End: 1, SourceChecksum: "owned", Objects: []domain.Object{object}}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		if _, e := r.CursorWithin(sc, seg); e != nil {
			return e
		}
		if e := r.CommitWithin(sc, seg, b); e != nil {
			return e
		}
		return r.CommitManifestWithin(sc, domain.Manifest{BatchID: b.ID, Objects: b.Objects})
	}); e != nil {
		t.Fatal(e)
	}
	a := query.ActorRef{UserID: "u", AuthVersion: 1, CredentialKind: "session", CredentialID: "c"}
	var j query.Job
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		var e error
		j, e = r.SubmitWithin(sc, a, query.Filter{Source: "local", SiteIDs: []string{site}, From: at.Add(-time.Second), To: at.Add(time.Second)})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	cleaned := false
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return r.CleanupWithin(sc, b, func() error { cleaned = true; return nil })
	}); !errors.Is(e, domain.ErrQueryBusy) || cleaned {
		t.Fatal("active frozen local object was unlinked", e)
	}
	var claimed query.Input
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		var found bool
		var e error
		claimed, found, e = r.ClaimWithin(sc)
		if !found {
			return errors.New("missing job")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error { return r.CancelWithin(sc, j.ID) }); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return r.CompleteWithin(sc, claimed, []domain.QueryRow{{Status: 200}}, "")
	}); !errors.Is(e, domain.ErrIncomplete) {
		t.Fatal("late query result overwrote cancel", e)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return r.CleanupWithin(sc, b, func() error { cleaned = true; return nil })
	}); e != nil || !cleaned {
		t.Fatal("cancelled query kept object pinned", e)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		next, e := r.SubmitWithin(sc, a, query.Filter{Source: "local", SiteIDs: []string{site}, From: at.Add(-time.Second), To: at.Add(time.Second)})
		if e == nil && next.ManifestObjects != 0 {
			return errors.New("cleaned local artifact selected")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
