//go:build integration

package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/integration/ingressaccess"
	identityapp "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	identitypg "gatebeam/internal/modules/identity/infrastructure/postgres"
	app "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	ingresspg "gatebeam/internal/modules/ingress/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	p             *pgxpool.Pool
	s             *app.Service
	access        *access.Service
	admin, editor app.ActorRef
	ids           *credential.Opaque
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := testkit.Postgres(t)
	ids := credential.New()
	tx := postgres.NewRunner(p)
	catalog := &ingressaccess.Catalog{}
	a := access.New(tx, identitypg.New(), audit.New(), ids, catalog, time.Now)
	s := app.New(tx, ingresspg.New(), ingressaccess.Authorizer{Identity: a}, audit.New(), ids)
	catalog.Ingress = s
	f := &fixture{p: p, s: s, access: a, ids: ids}
	f.admin = f.actor(t, "admin")
	f.editor = f.actor(t, "editor")
	return f
}
func (f *fixture) actor(t *testing.T, role string) app.ActorRef {
	t.Helper()
	u, _ := f.ids.NewID()
	c, _ := f.ids.NewID()
	_, e := f.p.Exec(context.Background(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01',$2)`, u, role)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.p.Exec(context.Background(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$1,$1,1,now()+interval '1 hour')`, c, u)
	if e != nil {
		t.Fatal(e)
	}
	return app.ActorRef{UserID: u, AuthVersion: 1, CredentialKind: "session", CredentialID: c}
}
func (f *fixture) grant(t *testing.T, a app.ActorRef, kind, id string) {
	t.Helper()
	if _, e := f.p.Exec(context.Background(), `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,$2,$3)`, a.UserID, kind, id); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) site(t *testing.T, name string, groups []string) domain.Site {
	t.Helper()
	v, e := f.s.CreateSite(context.Background(), f.admin, app.CreateSite{Name: name, GroupIDs: groups, Config: domain.SiteConfig{Enabled: true, Domains: []string{name + ".example.test"}}})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *fixture) target(t *testing.T) domain.TargetGroup {
	t.Helper()
	v, e := f.s.SaveTarget(context.Background(), f.admin, domain.TargetGroup{Config: domain.TargetConfig{Name: "shared", Protocol: "http", Members: []domain.TargetMember{{Address: "app.internal", Port: 8080, Weight: 1}}, AllowedNetworks: []string{"10.0.0.0/8"}}}, 0)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *fixture) reference(t *testing.T, s domain.Site, target domain.TargetGroup) domain.Site {
	t.Helper()
	cfg := s.Draft
	cfg.DefaultTarget = domain.TargetRef{ID: target.ID}
	v, e := f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, s.Revision)
	if e != nil {
		t.Fatal(e)
	}
	s.Revision = v.Number
	s.Draft = cfg
	return s
}
func TestSharedResourceChecksUnselectedDraftReferences(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a", nil)
	b := f.site(t, "b", nil)
	target := f.target(t)
	f.reference(t, a, target)
	f.reference(t, b, target)
	f.grant(t, f.editor, "site", a.ID)
	target.Config.Name = "changed"
	if _, e := f.s.SaveTarget(context.Background(), f.editor, target, target.Revision); !errors.Is(e, app.ErrDenied) {
		t.Fatalf("out of scope draft reference allowed: %v", e)
	}
	if e := f.s.DeleteTarget(context.Background(), f.admin, target.ID, target.Revision); !errors.Is(e, domain.ErrReferenced) {
		t.Fatalf("referenced deletion: %v", e)
	}
}
func TestGroupDeletePreservesSites(t *testing.T) {
	f := setup(t)
	g, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "team"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	s := f.site(t, "grouped", []string{g.ID})
	f.grant(t, f.editor, "group", g.ID)
	if _, e = f.s.Site(context.Background(), f.editor, s.ID); e != nil {
		t.Fatal(e)
	}
	if e = f.s.DeleteGroup(context.Background(), f.admin, g.ID, g.Revision); e != nil {
		t.Fatal(e)
	}
	v, e := f.s.Site(context.Background(), f.admin, s.ID)
	if e != nil || len(v.GroupIDs) != 0 {
		t.Fatalf("site lost or still grouped: %#v %v", v, e)
	}
	if _, e = f.s.Site(context.Background(), f.editor, s.ID); !errors.Is(e, app.ErrDenied) {
		t.Fatalf("deleted group scope remained: %v", e)
	}
}
func TestSaveDraftDoesNotMutatePublished(t *testing.T) {
	f := setup(t)
	s := f.site(t, "published", nil)
	if _, e := f.p.Exec(context.Background(), `UPDATE ingress_sites SET published_revision=draft_revision WHERE id=$1`, s.ID); e != nil {
		t.Fatal(e)
	}
	cfg := s.Draft
	cfg.Maintenance.Enabled = true
	v, e := f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, s.Revision)
	if e != nil {
		t.Fatal(e)
	}
	got, e := f.s.Site(context.Background(), f.admin, s.ID)
	if e != nil {
		t.Fatal(e)
	}
	if v.Number != 2 || got.PublishedRevision != 1 || got.Published == nil || got.Published.Maintenance.Enabled {
		t.Fatal("draft changed published", got)
	}
	if _, e = f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, 1); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("stale revision accepted", e)
	}
}
func TestEditorCreationAndCredentialProvenance(t *testing.T) {
	f := setup(t)
	g, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "team"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	f.grant(t, f.editor, "group", g.ID)
	v, e := f.s.CreateSite(context.Background(), f.editor, app.CreateSite{Name: "own", GroupIDs: []string{g.ID}, Config: domain.SiteConfig{Enabled: true, Domains: []string{"own.example.test"}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateSite(context.Background(), f.editor, app.CreateSite{Name: "global", Config: domain.SiteConfig{Enabled: true, Domains: []string{"global.example.test"}}}); !errors.Is(e, app.ErrDenied) {
		t.Fatal("editor global creation", e)
	}
	if e = f.s.SetGroups(context.Background(), f.editor, v.ID, nil, v.Revision); !errors.Is(e, app.ErrDenied) {
		t.Fatal("editor moved groups", e)
	}
	var n int
	if e = f.p.QueryRow(context.Background(), `SELECT count(*) FROM identity_grants WHERE account_id=$1 AND kind='site'`, f.editor.UserID).Scan(&n); e != nil || n != 0 {
		t.Fatal("creator privilege", e, n)
	}
	for _, a := range []app.ActorRef{{UserID: f.editor.UserID, AuthVersion: 1}, {UserID: f.editor.UserID, AuthVersion: 1, CredentialKind: "session", CredentialID: f.admin.CredentialID}} {
		if _, e = f.s.Site(context.Background(), a, v.ID); e == nil {
			t.Fatal("forged actor accepted")
		}
	}
	if e = f.access.Require(context.Background(), identityapp.Actor{UserID: f.admin.UserID, AuthVersion: 1, CredentialKind: "session", CredentialID: f.admin.CredentialID}, identityapp.View, []string{"00000000-0000-4000-8000-999999999999"}); e == nil {
		t.Fatal("unknown site accepted")
	}
}

type lockedStore struct {
	*ingresspg.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *lockedStore) WriteLock(sc transaction.Scope) error {
	if e := r.Store.WriteLock(sc); e != nil {
		return e
	}
	r.once.Do(func() {
		close(r.entered)
		select {
		case <-r.release:
		case <-sc.Context().Done():
		}
	})
	return sc.Context().Err()
}
func (f *fixture) heldService() (*app.Service, *lockedStore) {
	r := &lockedStore{Store: ingresspg.New(), entered: make(chan struct{}), release: make(chan struct{})}
	return app.New(postgres.NewRunner(f.p), r, ingressaccess.Authorizer{Identity: f.access}, audit.New(), f.ids), r
}
func waitEntered(t *testing.T, r *lockedStore) {
	t.Helper()
	select {
	case <-r.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("graph writer deadline")
	}
}
func result(t *testing.T, c <-chan error) error {
	t.Helper()
	select {
	case e := <-c:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("mutation deadlocked")
		return nil
	}
}
func TestTwoEditorsSerializeWithoutGraphLockUpgrade(t *testing.T) {
	f := setup(t)
	s := f.site(t, "race", nil)
	f.grant(t, f.editor, "site", s.ID)
	other := f.actor(t, "editor")
	f.grant(t, other, "site", s.ID)
	held, r := f.heldService()
	done := make(chan error, 1)
	go func() {
		_, e := held.SaveDraft(context.Background(), f.editor, app.Draft{SiteID: s.ID, Config: s.Draft}, 1)
		done <- e
	}()
	waitEntered(t, r)
	second := make(chan error, 1)
	go func() {
		_, e := f.s.SaveDraft(context.Background(), other, app.Draft{SiteID: s.ID, Config: s.Draft}, 1)
		second <- e
	}()
	select {
	case e := <-second:
		t.Fatalf("second writer crossed graph lock: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(r.release)
	if e := result(t, done); e != nil {
		t.Fatal(e)
	}
	if e := result(t, second); !errors.Is(e, domain.ErrConflict) {
		t.Fatalf("stale second editor: %v", e)
	}
}
func TestCredentialRevocationOrdersWithIngressWriter(t *testing.T) {
	f := setup(t)
	s := f.site(t, "revoke", nil)
	f.grant(t, f.editor, "site", s.ID)
	held, r := f.heldService()
	done := make(chan error, 1)
	go func() {
		_, e := held.SaveDraft(context.Background(), f.editor, app.Draft{SiteID: s.ID, Config: s.Draft}, 1)
		done <- e
	}()
	waitEntered(t, r)
	revoke := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		revoke <- postgres.NewRunner(f.p).Within(ctx, func(sc transaction.Scope) error {
			if e := identitypg.New().Lock(sc); e != nil {
				return e
			}
			return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE identity_sessions SET revoked=true WHERE id=$1`, f.editor.CredentialID)
				return e
			})
		})
	}()
	select {
	case e := <-revoke:
		t.Fatalf("revoke crossed identity read lock: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(r.release)
	if e := result(t, done); e != nil {
		t.Fatal(e)
	}
	if e := result(t, revoke); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.SaveDraft(context.Background(), f.editor, app.Draft{SiteID: s.ID, Config: s.Draft}, 2); !errors.Is(e, app.ErrDenied) {
		t.Fatal("revoked credential survived", e)
	}
}
func TestReferenceCreationFreezesSharedResourceAuthority(t *testing.T) {
	f := setup(t)
	a := f.site(t, "allowed", nil)
	b := f.site(t, "outside", nil)
	target := f.target(t)
	f.reference(t, a, target)
	f.grant(t, f.editor, "site", a.ID)
	outside := f.actor(t, "editor")
	f.grant(t, outside, "site", b.ID)
	held, r := f.heldService()
	done := make(chan error, 1)
	cfg := b.Draft
	cfg.DefaultTarget = domain.TargetRef{ID: target.ID}
	go func() {
		_, e := held.SaveDraft(context.Background(), outside, app.Draft{SiteID: b.ID, Config: cfg}, 1)
		done <- e
	}()
	waitEntered(t, r)
	change := make(chan error, 1)
	go func() {
		target.Config.Name = "race"
		_, e := f.s.SaveTarget(context.Background(), f.editor, target, 1)
		change <- e
	}()
	select {
	case e := <-change:
		t.Fatalf("edit crossed new reference transaction: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(r.release)
	if e := result(t, done); e != nil {
		t.Fatal(e)
	}
	if e := result(t, change); !errors.Is(e, app.ErrDenied) {
		t.Fatal("new unauthorized draft reference missed", e)
	}
	got, e := f.s.Target(context.Background(), f.admin, target.ID)
	if e != nil || got.Revision != 1 {
		t.Fatal("denied mutation committed", e)
	}
}
func TestGlobalDomainUniquenessAndPublishedClaims(t *testing.T) {
	f := setup(t)
	done := make(chan error, 2)
	for _, host := range []string{" Unique.EXAMPLE.Test. ", "unique.example.test"} {
		host := host
		go func() {
			_, e := f.s.CreateSite(context.Background(), f.admin, app.CreateSite{Name: "same", Config: domain.SiteConfig{Enabled: true, Domains: []string{host}}})
			done <- e
		}()
	}
	a, b := result(t, done), result(t, done)
	if (a == nil) == (b == nil) || (!(errors.Is(a, domain.ErrConflict)) && !(errors.Is(b, domain.ErrConflict))) {
		t.Fatal("concurrent duplicate domains", a, b)
	}
	s := f.site(t, "reserved", nil)
	if _, e := f.p.Exec(context.Background(), `UPDATE ingress_sites SET published_revision=1 WHERE id=$1`, s.ID); e != nil {
		t.Fatal(e)
	}
	s.Draft.Domains = []string{"changed.example.test"}
	if _, e := f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: s.Draft}, 1); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.CreateSite(context.Background(), f.admin, app.CreateSite{Name: "claim", Config: domain.SiteConfig{Enabled: true, Domains: []string{"reserved.example.test"}}}); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("published domain claim lost", e)
	}
}
func TestSharedReferencesAboveIdentityCallBound(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		cfg := domain.SiteConfig{Enabled: true, Domains: []string{fmt.Sprintf("many%d.example.test", i)}, DefaultTarget: domain.TargetRef{ID: target.ID}}
		if e := cfg.Normalize(); e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(cfg)
		if e := postgres.NewRunner(f.p).Within(context.Background(), func(sc transaction.Scope) error {
			return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
				if _, e := tx.Exec(ctx, `INSERT INTO ingress_sites(id,name,draft_revision) VALUES($1::uuid,$1::text,1)`, ids[i]); e != nil {
					return e
				}
				_, e := tx.Exec(ctx, `INSERT INTO ingress_site_revisions(site_id,revision,config) VALUES($1,1,$2)`, ids[i], b)
				return e
			})
		}); e != nil {
			t.Fatal(e)
		}
		f.grant(t, f.editor, "site", ids[i])
	}
	target.Config.Name = "all 101"
	if _, e := f.s.SaveTarget(context.Background(), f.editor, target, 1); e != nil {
		t.Fatalf("valid closure truncated at 100: %v", e)
	}
	if _, e := f.p.Exec(context.Background(), `DELETE FROM identity_grants WHERE account_id=$1 AND resource_id=$2`, f.editor.UserID, ids[100]); e != nil {
		t.Fatal(e)
	}
	target.Config.Name = "deny last"
	if _, e := f.s.SaveTarget(context.Background(), f.editor, target, 2); !errors.Is(e, app.ErrDenied) {
		t.Fatal("last closure member skipped", e)
	}
}

func TestCatalogDistinguishesCurrentMembershipAndUnknownSite(t *testing.T) {
	f := setup(t)
	g, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "catalog"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	grouped := f.site(t, "grouped", []string{g.ID})
	ungrouped := f.site(t, "ungrouped", nil)
	deleted := f.site(t, "deleted", nil)
	if e := f.s.DeleteSite(context.Background(), f.admin, deleted.ID, deleted.Revision); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct {
		id   string
		want []string
		err  error
	}{
		{grouped.ID, []string{g.ID}, nil},
		{ungrouped.ID, nil, nil},
		{deleted.ID, nil, nil},
		{"11111111-1111-4111-8111-111111111111", nil, domain.ErrNotFound},
		{"invalid", nil, domain.ErrNotFound},
	} {
		e := postgres.NewRunner(f.p).Within(context.Background(), func(sc transaction.Scope) error {
			got, e := f.s.SiteGroupsWithin(sc, v.id)
			if !errors.Is(e, v.err) || strings.Join(got, ",") != strings.Join(v.want, ",") {
				t.Errorf("site %s membership=%v error=%v; want %v error=%v", v.id, got, e, v.want, v.err)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
}

type badAudit struct{}

func (badAudit) Append(transaction.Scope, audit.Event) error { return errors.New("audit unavailable") }
func TestAuditFailureRollsBackRevisionAndDomainClaims(t *testing.T) {
	f := setup(t)
	s := f.site(t, "rollback", nil)
	fail := app.New(postgres.NewRunner(f.p), ingresspg.New(), ingressaccess.Authorizer{Identity: f.access}, badAudit{}, f.ids)
	cfg := s.Draft
	cfg.Domains = []string{"failed.example.test"}
	if _, e := fail.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, 1); e == nil {
		t.Fatal("audit failure ignored")
	}
	got, e := f.s.Site(context.Background(), f.admin, s.ID)
	if e != nil || got.Revision != 1 || got.Draft.Domains[0] != "rollback.example.test" {
		t.Fatal("partial commit", e, got)
	}
	if _, e = f.s.CreateSite(context.Background(), f.admin, app.CreateSite{Name: "claim", Config: cfg}); e != nil {
		t.Fatal("rolled back claim remained", e)
	}
}
func TestIndependentTargetHeadsAndReleaseExport(t *testing.T) {
	f := setup(t)
	a := f.site(t, "publishedsite", nil)
	b := f.site(t, "unselected", nil)
	target := f.target(t)
	a = f.reference(t, a, target)
	b = f.reference(t, b, target)
	if _, e := f.p.Exec(context.Background(), `UPDATE ingress_sites SET published_revision=draft_revision WHERE id=$1`, a.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.p.Exec(context.Background(), `UPDATE ingress_targets SET published_revision=draft_revision WHERE id=$1`, target.ID); e != nil {
		t.Fatal(e)
	}
	target.Config.Name = "newtarget"
	target, e := f.s.SaveTarget(context.Background(), f.admin, target, 1)
	if e != nil {
		t.Fatal(e)
	}
	cfg := b.Draft
	cfg.Maintenance.Enabled = true
	if _, e = f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: b.ID, Config: cfg}, b.Revision); e != nil {
		t.Fatal(e)
	}
	var export app.ReleaseInputs
	e = postgres.NewRunner(f.p).Within(context.Background(), func(sc transaction.Scope) error {
		actor := identityapp.Actor{UserID: f.admin.UserID, AuthVersion: 1, CredentialKind: "session", CredentialID: f.admin.CredentialID}
		if e := f.access.GuardWithin(sc, actor); e != nil {
			return e
		}
		var e error
		export, e = f.s.ReadForReleaseWithin(sc, nil, map[string]int64{"target:" + target.ID: 2})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(export.Export.Sites) != 1 || export.Export.Sites[0].ID != a.ID || len(export.AuthorizationSiteIDs) != 2 || export.Export.Targets[0].PublishedRevision != 1 || export.Export.Targets[0].Revision != 2 {
		t.Fatalf("release selection/authority conflated: %#v", export)
	}
	got, e := f.s.Site(context.Background(), f.admin, a.ID)
	if e != nil || got.Revision != a.Revision || got.PublishedRevision != a.Revision {
		t.Fatal("target edit mutated site", e)
	}
	export.Export.Targets[0].Config.Name = "mutated export"
	target, e = f.s.Target(context.Background(), f.admin, target.ID)
	if e != nil || target.Config.Name != "newtarget" {
		t.Fatal("mutable export persisted", e)
	}
}

func TestIdempotencyRepeatConcurrentConflictAndRevocation(t *testing.T) {
	f := setup(t)
	in := app.Mutation{Kind: "site.create", Site: &app.CreateSite{Name: "idem", Config: domain.SiteConfig{Enabled: true, Domains: []string{"idem.example.test"}}}}
	key := "site-create-001"
	done := make(chan struct {
		v app.Revision
		e error
	}, 2)
	for range 2 {
		go func() {
			v, e := f.s.Mutate(context.Background(), f.admin, in, key)
			done <- struct {
				v app.Revision
				e error
			}{v, e}
		}()
	}
	a, b := <-done, <-done
	if a.e != nil || b.e != nil || a.v != b.v {
		t.Fatal("concurrent replay", a, b)
	}
	var n int
	if e := f.p.QueryRow(context.Background(), `SELECT count(*) FROM audit WHERE action='ingress.site.created'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("duplicate audit", e, n)
	}
	changed := in
	changed.Site = &app.CreateSite{Name: "different", Config: domain.SiteConfig{Enabled: true, Domains: []string{"other.example.test"}}}
	if _, e := f.s.Mutate(context.Background(), f.admin, changed, key); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("key payload collision", e)
	}
	if _, e := f.p.Exec(context.Background(), `UPDATE identity_sessions SET revoked=true WHERE id=$1`, f.admin.CredentialID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.Mutate(context.Background(), f.admin, in, key); !errors.Is(e, app.ErrDenied) {
		t.Fatal("receipt bypassed revoke", e)
	}
}
func TestIdempotencyRechecksFullReferenceClosureAndRollback(t *testing.T) {
	f := setup(t)
	a := f.site(t, "idema", nil)
	b := f.site(t, "idemb", nil)
	target := f.target(t)
	f.reference(t, a, target)
	f.grant(t, f.editor, "site", a.ID)
	cfg := target.Config
	cfg.Name = "idempotent edit"
	in := app.Mutation{Kind: "target.save", ResourceID: target.ID, Expected: 1, Target: &cfg}
	if _, e := f.s.Mutate(context.Background(), f.editor, in, "shared-key"); e != nil {
		t.Fatal(e)
	}
	f.reference(t, b, target)
	if _, e := f.s.Mutate(context.Background(), f.editor, in, "shared-key"); !errors.Is(e, app.ErrDenied) {
		t.Fatal("receipt bypassed new reference", e)
	}
	fail := app.New(postgres.NewRunner(f.p), ingresspg.New(), ingressaccess.Authorizer{Identity: f.access}, badAudit{}, f.ids)
	create := app.Mutation{Kind: "group.save", GroupName: "rollback"}
	if _, e := fail.Mutate(context.Background(), f.admin, create, "failed-key"); e == nil {
		t.Fatal("audit failure swallowed")
	}
	var n int
	if e := f.p.QueryRow(context.Background(), `SELECT count(*) FROM ingress_idempotency WHERE idempotency_key='failed-key'`).Scan(&n); e != nil || n != 0 {
		t.Fatal("failed mutation receipt committed", e, n)
	}
	if _, e := f.s.Mutate(context.Background(), f.admin, create, "failed-key"); e != nil {
		t.Fatal("failed key not retryable", e)
	}
}

func TestSiteDeletionTombstoneReauthorizesReplay(t *testing.T) {
	f := setup(t)
	g, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "temporary"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	s := f.site(t, "delete", []string{g.ID})
	f.grant(t, f.editor, "group", g.ID)
	m := app.Mutation{Kind: "site.delete", ResourceID: s.ID, Expected: 1}
	first, e := f.s.Mutate(context.Background(), f.editor, m, "delete-key")
	if e != nil {
		t.Fatal(e)
	}
	second, e := f.s.Mutate(context.Background(), f.editor, m, "delete-key")
	if e != nil || first != second {
		t.Fatal("delete replay failed", e)
	}
	if _, e = f.s.Site(context.Background(), f.admin, s.ID); !errors.Is(e, app.ErrDenied) && !errors.Is(e, domain.ErrNotFound) {
		t.Fatal("tombstone visible", e)
	}
	sites, e := f.s.Sites(context.Background(), f.admin, 100, 0)
	if e != nil || len(sites) != 0 {
		t.Fatal("tombstone listed", e, sites)
	}
	if e = f.s.DeleteGroup(context.Background(), f.admin, g.ID, 1); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Mutate(context.Background(), f.editor, m, "delete-key"); !errors.Is(e, app.ErrDenied) {
		t.Fatal("deleted group authorized receipt", e)
	}
	if _, e = f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: s.Draft}, 1); !errors.Is(e, app.ErrDenied) {
		t.Fatal("tombstone edited", e)
	}
}

func TestPermissionChangeWaitsForIngressWriter(t *testing.T) {
	f := setup(t)
	s := f.site(t, "permission", nil)
	f.grant(t, f.editor, "site", s.ID)
	held, r := f.heldService()
	done := make(chan error, 1)
	go func() {
		_, e := held.SaveDraft(context.Background(), f.editor, app.Draft{SiteID: s.ID, Config: s.Draft}, 1)
		done <- e
	}()
	waitEntered(t, r)
	revoke := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		revoke <- postgres.NewRunner(f.p).Within(ctx, func(sc transaction.Scope) error {
			repo := identitypg.New()
			if e := repo.Lock(sc); e != nil {
				return e
			}
			return repo.ReplaceGrants(sc, f.editor.UserID, nil)
		})
	}()
	select {
	case e := <-revoke:
		t.Fatalf("permission change crossed management mutation: %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(r.release)
	if e := result(t, done); e != nil {
		t.Fatal(e)
	}
	if e := result(t, revoke); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.SaveDraft(context.Background(), f.editor, app.Draft{SiteID: s.ID, Config: s.Draft}, 2); !errors.Is(e, app.ErrDenied) {
		t.Fatal("post-revoke grant survived", e)
	}
}
func TestScopedTokenCannotEditSharedTargetOutsideOwnSites(t *testing.T) {
	f := setup(t)
	a := f.site(t, "tokena", nil)
	b := f.site(t, "tokenb", nil)
	target := f.target(t)
	f.reference(t, a, target)
	f.reference(t, b, target)
	f.grant(t, f.editor, "site", a.ID)
	f.grant(t, f.editor, "site", b.ID)
	id, _ := f.ids.NewID()
	_, e := f.p.Exec(context.Background(), `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['edit'],ARRAY[$3],now()+interval '1 hour')`, id, f.editor.UserID, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	token := f.editor
	token.CredentialKind = "token"
	token.CredentialID = id
	if _, e = f.s.SaveTarget(context.Background(), token, target, 1); !errors.Is(e, app.ErrDenied) {
		t.Fatal("narrow token recovered account-wide scope", e)
	}
}
func TestIdempotencyCanonicalCommandCredentialIsolationAndExpiry(t *testing.T) {
	f := setup(t)
	m := app.Mutation{Kind: "site.create", Site: &app.CreateSite{Name: "normalize", Config: domain.SiteConfig{Enabled: true, Domains: []string{"canonical.example.test"}}}}
	first, e := f.s.Mutate(context.Background(), f.admin, m, "normalize-key")
	if e != nil {
		t.Fatal(e)
	}
	m.Site.Name = " normalize "
	m.Site.Config.Domains = []string{" CANONICAL.Example.Test. "}
	m.Site.Config.Routes = []domain.Route{}
	again, e := f.s.Mutate(context.Background(), f.admin, m, "normalize-key")
	if e != nil || first != again {
		t.Fatal("equivalent normalized command conflicted", e)
	}
	m = app.Mutation{Kind: "group.save", GroupName: "first"}
	group, e := f.s.Mutate(context.Background(), f.admin, m, "credential-key")
	if e != nil {
		t.Fatal(e)
	}
	other := f.admin
	other.CredentialID, _ = f.ids.NewID()
	_, e = f.p.Exec(context.Background(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$1,$1,1,now()+interval '1 hour')`, other.CredentialID, other.UserID)
	if e != nil {
		t.Fatal(e)
	}
	second, e := f.s.Mutate(context.Background(), other, m, "credential-key")
	if e != nil || group == second {
		t.Fatal("receipt crossed credential", e)
	}
	if _, e = f.p.Exec(context.Background(), `UPDATE ingress_idempotency SET expires=now()-interval '1 second' WHERE credential_id=$1 AND idempotency_key='credential-key'`, f.admin.CredentialID); e != nil {
		t.Fatal(e)
	}
	m.GroupName = "after expiry"
	third, e := f.s.Mutate(context.Background(), f.admin, m, "credential-key")
	if e != nil || group == third {
		t.Fatal("expired receipt not replaced", e)
	}
	for _, key := range []string{"bad key", strings.Repeat("x", 129)} {
		if _, e = f.s.Mutate(context.Background(), f.admin, m, key); !errors.Is(e, domain.ErrInvalid) {
			t.Fatal("unbounded key", e)
		}
	}
}

func TestReleaseExportOmitsUnselectedDraftAndKeepsMaterialVersions(t *testing.T) {
	f := setup(t)
	s := f.site(t, "export", nil)
	material, _ := f.ids.NewID()
	cfg := s.Draft
	cfg.EntryCertificate = &domain.MaterialRef{ID: material, Revision: 1, Status: "unavailable"}
	rev, e := f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.p.Exec(context.Background(), `UPDATE ingress_sites SET published_revision=draft_revision WHERE id=$1`, s.ID); e != nil {
		t.Fatal(e)
	}
	cfg.EntryCertificate.Revision = 2
	cfg.Maintenance.Enabled = true
	rev, e = f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, rev.Number)
	if e != nil {
		t.Fatal(e)
	}
	read := func(selected []string, expected map[string]int64) app.ReleaseInputs {
		t.Helper()
		var out app.ReleaseInputs
		if e := postgres.NewRunner(f.p).Within(context.Background(), func(sc transaction.Scope) error {
			actor := identityapp.Actor{UserID: f.admin.UserID, AuthVersion: 1, CredentialKind: "session", CredentialID: f.admin.CredentialID}
			if e := f.access.GuardWithin(sc, actor); e != nil {
				return e
			}
			var e error
			out, e = f.s.ReadForReleaseWithin(sc, selected, expected)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		return out
	}
	out := read(nil, nil)
	b, _ := json.Marshal(out.Export.Sites[0])
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if _, ok := fields["draft"]; ok {
		t.Fatal("unselected site draft crossed export boundary")
	}
	out = read([]string{s.ID}, map[string]int64{"site:" + s.ID: rev.Number})
	if len(out.Export.Certificates) != 2 {
		t.Fatal("distinct immutable material versions collapsed", out.Export.Certificates)
	}
}

func TestPublishedReferencesRemainProtectedAfterDraftRemoval(t *testing.T) {
	f := setup(t)
	a := f.site(t, "puballowed", nil)
	b := f.site(t, "puboutside", nil)
	target := f.target(t)
	a = f.reference(t, a, target)
	b = f.reference(t, b, target)
	for _, s := range []domain.Site{a, b} {
		if _, e := f.p.Exec(context.Background(), `UPDATE ingress_sites SET published_revision=draft_revision WHERE id=$1`, s.ID); e != nil {
			t.Fatal(e)
		}
		cfg := s.Draft
		cfg.DefaultTarget = domain.TargetRef{}
		if _, e := f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, s.Revision); e != nil {
			t.Fatal(e)
		}
	}
	f.grant(t, f.editor, "site", a.ID)
	if _, e := f.s.SaveTarget(context.Background(), f.editor, target, 1); !errors.Is(e, app.ErrDenied) {
		t.Fatal("unselected published reference ignored", e)
	}
	if e := f.s.DeleteTarget(context.Background(), f.admin, target.ID, 1); !errors.Is(e, domain.ErrReferenced) {
		t.Fatal("published-only references allowed deletion", e)
	}
}
func TestGroupDeleteRacesWithEditorCreation(t *testing.T) {
	for _, deleteFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(deleteFirst), func(t *testing.T) {
			f := setup(t)
			g, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "race group"}, 0)
			if e != nil {
				t.Fatal(e)
			}
			f.grant(t, f.editor, "group", g.ID)
			held, r := f.heldService()
			create := func(s *app.Service) error {
				_, e := s.CreateSite(context.Background(), f.editor, app.CreateSite{Name: "new", GroupIDs: []string{g.ID}, Config: domain.SiteConfig{Enabled: true, Domains: []string{"grouprace.example.test"}}})
				return e
			}
			remove := func(s *app.Service) error { return s.DeleteGroup(context.Background(), f.admin, g.ID, 1) }
			first, second := create, remove
			if deleteFirst {
				first, second = remove, create
			}
			a, b := make(chan error, 1), make(chan error, 1)
			go func() { a <- first(held) }()
			waitEntered(t, r)
			go func() { b <- second(f.s) }()
			select {
			case e := <-b:
				t.Fatalf("group/member mutation crossed graph lock: %v", e)
			case <-time.After(100 * time.Millisecond):
			}
			close(r.release)
			if e := result(t, a); e != nil {
				t.Fatal(e)
			}
			e = result(t, b)
			if deleteFirst {
				if !errors.Is(e, domain.ErrNotFound) {
					t.Fatal("creation in deleted group accepted", e)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				sites, e := f.s.Sites(context.Background(), f.admin, 100, 0)
				if e != nil || len(sites) != 1 || len(sites[0].GroupIDs) != 0 {
					t.Fatal("delete failed to preserve/unlink new site", e, sites)
				}
			}
		})
	}
}

func TestDisableDraftPreservesPublishedActivation(t *testing.T) {
	f := setup(t)
	s := f.site(t, "enabled", nil)
	if !s.Draft.Enabled {
		t.Fatal("fixture must explicitly enable")
	}
	if _, e := f.p.Exec(context.Background(), `UPDATE ingress_sites SET published_revision=draft_revision WHERE id=$1`, s.ID); e != nil {
		t.Fatal(e)
	}
	cfg := s.Draft
	cfg.Enabled = false
	if _, e := f.s.SaveDraft(context.Background(), f.admin, app.Draft{SiteID: s.ID, Config: cfg}, 1); e != nil {
		t.Fatal(e)
	}
	got, e := f.s.Site(context.Background(), f.admin, s.ID)
	if e != nil || got.Draft.Enabled || got.Published == nil || !got.Published.Enabled || got.PublishedRevision != 1 {
		t.Fatal("draft deactivation altered published state", e, got)
	}
}

func TestCreateReceiptReauthorizesResultSiteCurrentScope(t *testing.T) {
	f := setup(t)
	g, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "original"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	h, e := f.s.SaveGroup(context.Background(), f.admin, domain.SiteGroup{Name: "destination"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	f.grant(t, f.editor, "group", g.ID)
	m := app.Mutation{Kind: "site.create", Site: &app.CreateSite{Name: "moved", GroupIDs: []string{g.ID}, Config: domain.SiteConfig{Enabled: true, Domains: []string{"moved.example.test"}}}}
	first, e := f.s.Mutate(context.Background(), f.editor, m, "moved-create")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.s.SetGroups(context.Background(), f.admin, first.ResourceID, []string{h.ID}, first.Number); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Site(context.Background(), f.editor, first.ResourceID); !errors.Is(e, app.ErrDenied) {
		t.Fatal("moved site remained visible", e)
	}
	if _, e = f.s.Mutate(context.Background(), f.editor, m, "moved-create"); !errors.Is(e, app.ErrDenied) {
		t.Fatal("create receipt bypassed result's current scope", e)
	}
	if e = f.s.DeleteSite(context.Background(), f.admin, first.ResourceID, 2); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Mutate(context.Background(), f.editor, m, "moved-create"); !errors.Is(e, app.ErrDenied) {
		t.Fatal("tombstone receipt bypassed current scope", e)
	}
	f.grant(t, f.editor, "group", h.ID)
	if e = f.s.DeleteGroup(context.Background(), f.admin, g.ID, 1); e != nil {
		t.Fatal(e)
	}
	again, e := f.s.Mutate(context.Background(), f.editor, m, "moved-create")
	if e != nil || again != first {
		t.Fatal("current authorized result scope must supersede original group", e, again)
	}
}
func TestTargetIPv6LiteralPolicy(t *testing.T) {
	f := setup(t)
	for _, address := range []string{"fd00::1", "FD00:0000:0000:0000:0000:0000:0000:0001", "::1", "fe80::1", "ff02::1", "::", "2001:db8::1", "fd00::1%en0"} {
		cfg := domain.TargetConfig{Name: "ipv6", Protocol: "http", Members: []domain.TargetMember{{Address: address, Port: 8080, Weight: 1}}, HTTPHost: "business.example.test", AllowedNetworks: []string{"fd00::/64"}}
		v, e := f.s.SaveTarget(context.Background(), f.admin, domain.TargetGroup{Config: cfg}, 0)
		valid := address == "fd00::1" || strings.HasPrefix(address, "FD00:")
		if valid {
			if e != nil || v.Config.Members[0].Address != "fd00::1" || v.Config.HTTPHost != "business.example.test" {
				t.Fatal("valid ULA rejected or Host changed", address, e, v)
			}
		} else if !errors.Is(e, domain.ErrInvalid) {
			t.Fatal("protected/out-of-scope/zoned IPv6 accepted", address, e)
		}
	}
}

func TestVerifiedPublicationKeepsDraftAndGuardsBase(t *testing.T) {
	f := setup(t)
	s := f.site(t, "verified", nil)
	ctx := context.Background()
	tx := postgres.NewRunner(f.p)
	// A newer draft must survive publishing the already verified revision.
	cfg := s.Draft
	cfg.Domains = []string{"new.example.test"}
	r, e := f.s.SaveDraft(ctx, f.admin, app.Draft{SiteID: s.ID, Config: cfg}, s.Revision)
	if e != nil {
		t.Fatal(e)
	}
	cmd := app.VerifiedPublication{PublishedBase: map[string]int64{"site:" + s.ID: 0}, Sites: []app.VerifiedSite{{ID: s.ID, Revision: s.Revision, Config: s.Draft}}}
	e = tx.Within(ctx, func(sc transaction.Scope) error { return f.s.CommitVerifiedWithin(sc, cmd) })
	if e != nil {
		t.Fatal(e)
	}
	var draft, published int64
	if e = f.p.QueryRow(ctx, "SELECT draft_revision,published_revision FROM ingress_sites WHERE id=$1", s.ID).Scan(&draft, &published); e != nil || draft != r.Number || published != s.Revision {
		t.Fatalf("heads %d/%d %v", draft, published, e)
	}
	var claims int
	if e = f.p.QueryRow(ctx, "SELECT count(*) FROM ingress_domains WHERE site_id=$1", s.ID).Scan(&claims); e != nil || claims != 2 {
		t.Fatalf("draft/published domain claims %d %v", claims, e)
	}
	e = tx.Within(ctx, func(sc transaction.Scope) error { return f.s.CommitVerifiedWithin(sc, cmd) })
	if !errors.Is(e, domain.ErrConflict) {
		t.Fatalf("stale base accepted: %v", e)
	}
}

func TestVerifiedPublicationDoesNotRequireUnexportedOrphanTargetBase(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	site := f.site(t, "orphan-target-base", nil)
	target := f.target(t)
	if _, e := f.p.Exec(ctx, "UPDATE ingress_targets SET published_revision=draft_revision WHERE id=$1", target.ID); e != nil {
		t.Fatal(e)
	}
	// Release export includes all published sites plus needed/selected targets,
	// not an unrelated target left published after its last site stopped using it.
	cmd := app.VerifiedPublication{PublishedBase: map[string]int64{"site:" + site.ID: 0}, Sites: []app.VerifiedSite{{ID: site.ID, Revision: site.Revision, Config: site.Draft}}}
	e := postgres.NewRunner(f.p).Within(ctx, func(sc transaction.Scope) error { return f.s.CommitVerifiedWithin(sc, cmd) })
	if e != nil {
		t.Fatalf("unrelated unexported target blocked publication: %v", e)
	}
}
