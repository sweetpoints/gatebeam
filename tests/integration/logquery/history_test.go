//go:build integration

package logquery_test

import (
	"errors"
	"gatebeam/internal/modules/observability/application/archive"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type permission struct{ denied bool }

func (p *permission) RequireWithin(transaction.Scope, query.ActorRef, []string) error {
	if p.denied {
		return domain.ErrDenied
	}
	return nil
}
func TestManifestWatermarkPaginationRevocationAndDeleteLifecycle(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	_, engine, m, _ := fixture(t)
	seg := domain.Segment{ID: strings.Repeat("b", 64), Path: "access.log", Fingerprint: "fp", Size: 1}
	b := domain.Batch{ID: "history-batch", SegmentID: seg.ID, Start: 0, End: 1, SourceChecksum: "abc", Objects: m.Objects}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if _, e := r.CursorWithin(sc, seg); e != nil {
			return e
		}
		return r.CommitWithin(sc, seg, b)
	}); e != nil {
		t.Fatal(e)
	}
	m.BatchID = b.ID
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if e := r.CommitManifestWithin(sc, m); e != nil {
			return e
		}
		return r.CleanedWithin(sc, m.BatchID)
	}); e != nil {
		t.Fatal(e)
	}
	permission := &permission{}
	service := query.New(tx, permission, r)
	a := query.ActorRef{UserID: "u", CredentialID: "c", CredentialKind: "session", AuthVersion: 1}
	f := query.Filter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}
	j, e := service.Submit(t.Context(), a, f)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.BeginDeleteWithin(sc, b.ID); return e }); !errors.Is(e, domain.ErrIncomplete) {
		t.Fatal("queued frozen manifest can be deleted", e)
	}
	c := query.NewCoordinator(service, engine)
	if e = c.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	page, e := service.Fetch(t.Context(), a, j.ID, "")
	if e != nil || page.Job.State != "succeeded" || len(page.Rows) != 1 {
		t.Fatal("history result", page, e)
	}
	permission.denied = true
	if _, e = service.Fetch(t.Context(), a, j.ID, ""); !errors.Is(e, domain.ErrDenied) {
		t.Fatal("cached result bypassed revoked permission", e)
	}
	permission.denied = false
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.BeginDeleteWithin(sc, b.ID); return e }); e != nil {
		t.Fatal(e)
	}
	j2, e := service.Submit(t.Context(), a, f)
	if e != nil || j2.ScanBytes != 0 {
		t.Fatal("deleting manifest remained queryable", e, j2)
	}
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error { return r.CommitManifestWithin(sc, m) }); e != nil {
		t.Fatal(e)
	}
	var state string
	if e = p.QueryRow(t.Context(), `SELECT state FROM observability_manifests WHERE batch_id=$1`, b.ID).Scan(&state); e != nil || state != "deleting" {
		t.Fatal("duplicate commit resurrected deleted manifest", state, e)
	}
}
func TestSourceRetirementIncarnationAndRecovery(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	seg := domain.Segment{ID: strings.Repeat("c", 64), Path: "access.20261107T120000.000000000.log", Fingerprint: "same-first-prefix", Size: 10, Closed: true}
	var old domain.Cursor
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { var e error; old, e = r.CursorWithin(sc, seg); return e }); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.BeginRetirement(sc, seg) }); !errors.Is(e, domain.ErrIncomplete) {
		t.Fatal("unread source retired", e)
	}
	b := domain.Batch{ID: "source-batch", SegmentID: seg.ID, Start: 0, End: 10, SourceChecksum: "sum"}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.CommitWithin(sc, seg, b) }); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.BeginRetirement(sc, seg) }); !errors.Is(e, domain.ErrIncomplete) {
		t.Fatal("unarchived source retired", e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if e := r.CommitManifestWithin(sc, domain.Manifest{BatchID: b.ID}); e != nil {
			return e
		}
		return r.BeginRetirement(sc, seg)
	}); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.CursorWithin(sc, seg); return e }); !errors.Is(e, domain.ErrIncomplete) {
		t.Fatal("retiring source accepted", e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		rs, e := r.Retirements(sc)
		if e != nil {
			return e
		}
		if len(rs) != 1 {
			return errors.New("lost retirement recovery")
		}
		return r.FinishRetirement(sc, rs[0].ID)
	}); e != nil {
		t.Fatal(e)
	}
	empty := seg
	empty.Fingerprint = ""
	empty.Size = 0
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.CursorWithin(sc, empty); return e }); !errors.Is(e, domain.ErrIncomplete) {
		t.Fatal("retired inode confused with fresh incomplete source", e)
	}
	var fresh domain.Cursor
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { var e error; fresh, e = r.CursorWithin(sc, seg); return e }); e != nil {
		t.Fatal(e)
	}
	if fresh.SegmentID == old.SegmentID || fresh.Offset != 0 {
		t.Fatal("reused inode reused cursor", old, fresh)
	}
}

func TestEmptyClosedSourceCanRetire(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	seg := domain.Segment{ID: strings.Repeat("d", 64), Path: "access.20261107T120000.000000001.log", Closed: true}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return r.BeginRetirement(sc, seg) }); e != nil {
		t.Fatal("empty closed rotation leaked", e)
	}
}

func TestArchiveManifestFailurePreservesLocalAndRetryCommitsOnce(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	store, _, m, root := fixture(t)
	seg := domain.Segment{ID: strings.Repeat("e", 64), Fingerprint: "fp", Path: "access.log", Size: 1}
	b := domain.Batch{ID: "archive-crash", SegmentID: seg.ID, Start: 0, End: 1, SourceChecksum: "sum", Objects: m.Objects}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if _, e := r.CursorWithin(sc, seg); e != nil {
			return e
		}
		return r.CommitWithin(sc, seg, b)
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(t.Context(), `CREATE FUNCTION fail_archive() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture manifest failure'; END $$; CREATE TRIGGER fail_manifest BEFORE INSERT ON observability_manifests FOR EACH ROW EXECUTE FUNCTION fail_archive()`); e != nil {
		t.Fatal(e)
	}
	service := archive.New(tx, r, store)
	if e := service.Step(t.Context()); e == nil {
		t.Fatal("manifest crash not injected")
	}
	if _, e := os.Stat(filepath.Join(root, m.Objects[0].Key)); e != nil {
		t.Fatal("uncommitted local object deleted", e)
	}
	if _, e := p.Exec(t.Context(), `DROP TRIGGER fail_manifest ON observability_manifests`); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e := service.Step(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e := p.QueryRow(t.Context(), `SELECT count(*) FROM observability_manifests`).Scan(&count); e != nil || count != 1 {
		t.Fatal("retry duplicate manifest", count, e)
	}
	if _, e := os.Stat(filepath.Join(root, m.Objects[0].Key)); !os.IsNotExist(e) {
		t.Fatal("committed local object not cleaned", e)
	}
}
