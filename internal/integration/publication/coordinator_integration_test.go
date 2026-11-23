//go:build integration

package publication_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/integration/ingressaccess"
	pub "gatebeam/internal/integration/publication"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	dd "gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	releasepg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	releasehttp "gatebeam/internal/modules/deployment/transport/http"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	identitypg "gatebeam/internal/modules/identity/infrastructure/postgres"
	ingress "gatebeam/internal/modules/ingress/application"
	id "gatebeam/internal/modules/ingress/domain"
	ingresspg "gatebeam/internal/modules/ingress/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type materials struct {
	fail            bool
	seen            []deploy.Material
	hook            func()
	historicalCheck func([]deploy.MaterialRequirement) error
	currentCheck    func([]deploy.Material) error
}

func (m *materials) ValidateHistoricalWithin(sc transaction.Scope, requirements []deploy.MaterialRequirement) error {
	if m.historicalCheck != nil {
		return m.historicalCheck(requirements)
	}
	if m.fail {
		return errors.New("current logical identity retired, incompatible or revoked")
	}
	for _, r := range requirements {
		if r.Ref.Kind == "certificate" && r.Usage == "serverAuth" && len(r.Names) == 0 {
			return errors.New("name binding absent")
		}
	}
	return nil
}
func (m *materials) ReadMaterialsWithin(sc transaction.Scope, v []deploy.Material) error {
	m.seen = append([]deploy.Material{}, v...)
	if m.currentCheck != nil {
		if e := m.currentCheck(v); e != nil {
			return e
		}
	}
	if m.hook != nil {
		m.hook()
	}
	if m.fail {
		return errors.New("secret private unrelated resource detail")
	}
	return nil
}

type fixture struct {
	p                *pgxpool.Pool
	tx               *postgres.Runner
	in               *ingress.Service
	access           *access.Service
	releases         *release.Service
	pub              *pub.Coordinator
	ids              *credential.Opaque
	admin, publisher pub.ActorRef
	materials        *materials
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	ids := credential.New()
	cat := &ingressaccess.Catalog{}
	ac := access.New(tx, identitypg.New(), audit.New(), ids, cat, time.Now)
	in := ingress.New(tx, ingresspg.New(), ingressaccess.Authorizer{Identity: ac}, audit.New(), ids)
	cat.Ingress = in
	r := release.New(releasepg.New(), ids)
	m := &materials{}
	f := &fixture{p: p, tx: tx, in: in, access: ac, releases: r, ids: ids, materials: m}
	f.admin = f.actor(t, "admin")
	f.publisher = f.actor(t, "publisher")
	f.pub = f.coordinator(m, jobs.New(p), audit.New())
	return f
}
func (f *fixture) coordinator(m pub.Materials, j pub.Jobs, a pub.Audit) *pub.Coordinator {
	return pub.New(f.tx, f.access, f.in, m, f.releases, j, a, f.ids)
}
func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, e := f.p.Exec(context.Background(), sql, args...); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) actor(t *testing.T, role string) pub.ActorRef {
	t.Helper()
	u, _ := f.ids.NewID()
	c, _ := f.ids.NewID()
	f.exec(t, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01',$2)`, u, role)
	f.exec(t, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$1,$1,1,now()+interval '1 hour')`, c, u)
	return pub.ActorRef{UserID: u, CredentialID: c, CredentialKind: "session", AuthVersion: 1}
}
func ia(a pub.ActorRef) ingress.ActorRef {
	return ingress.ActorRef{UserID: a.UserID, CredentialID: a.CredentialID, CredentialKind: a.CredentialKind, AuthVersion: a.AuthVersion}
}
func (f *fixture) grant(t *testing.T, a pub.ActorRef, site string) {
	f.exec(t, `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site',$2) ON CONFLICT DO NOTHING`, a.UserID, site)
}
func (f *fixture) site(t *testing.T, name string) id.Site {
	t.Helper()
	s, e := f.in.CreateSite(context.Background(), ia(f.admin), ingress.CreateSite{Name: name, Config: id.SiteConfig{Enabled: true, Domains: []string{name + ".example.test"}}})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *fixture) target(t *testing.T) id.TargetGroup {
	t.Helper()
	v, e := f.in.SaveTarget(context.Background(), ia(f.admin), id.TargetGroup{Config: id.TargetConfig{Name: "shared", Protocol: "http", Members: []id.TargetMember{{Address: "app.internal", Port: 8080, Weight: 1}}, AllowedNetworks: []string{"10.0.0.0/8"}}}, 0)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *fixture) save(t *testing.T, s id.Site) id.Site {
	t.Helper()
	r, e := f.in.SaveDraft(context.Background(), ia(f.admin), ingress.Draft{SiteID: s.ID, Config: s.Draft}, s.Revision)
	if e != nil {
		t.Fatal(e)
	}
	s.Revision = r.Number
	return s
}
func (f *fixture) ref(t *testing.T, s id.Site, target id.TargetGroup) id.Site {
	s.Draft.DefaultTarget = id.TargetRef{ID: target.ID}
	return f.save(t, s)
}

// Fixtures mark historical verified input explicitly. I2 never advances these heads.
func (f *fixture) publishedSite(t *testing.T, s id.Site) {
	f.exec(t, `UPDATE ingress_sites SET published_revision=draft_revision WHERE id=$1`, s.ID)
}
func (f *fixture) publishedTarget(t *testing.T, s id.TargetGroup) {
	f.exec(t, `UPDATE ingress_targets SET published_revision=draft_revision WHERE id=$1`, s.ID)
}
func (f *fixture) prepare(t *testing.T, a pub.ActorRef, sites []string, expected map[string]int64) pub.CandidateView {
	t.Helper()
	v, e := f.pub.Prepare(context.Background(), a, sites, expected)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *fixture) candidate(t *testing.T, v string) release.Candidate {
	t.Helper()
	var out release.Candidate
	if e := f.tx.Within(context.Background(), func(sc transaction.Scope) error { var e error; out, e = f.releases.ReadWithin(sc, v); return e }); e != nil {
		t.Fatal(e)
	}
	return out
}
func selected(s id.Site) map[string]int64 { return map[string]int64{"site:" + s.ID: s.Revision} }
func (f *fixture) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if e := f.p.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestSelectedReleaseKeepsOtherDraftUnpublished(t *testing.T) {
	f := setup(t)
	a, b := f.site(t, "a"), f.site(t, "private-b")
	f.publishedSite(t, a)
	f.publishedSite(t, b)
	b.Draft.Maintenance.Enabled = true
	b = f.save(t, b)
	a.Draft.Enabled = false
	a = f.save(t, a)
	f.grant(t, f.publisher, a.ID)
	v := f.prepare(t, f.publisher, []string{a.ID}, selected(a))
	c := f.candidate(t, v.ID)
	for _, s := range c.Snapshot.Sites {
		if s.ID == b.ID && (s.Revision != 1 || s.Config.Maintenance.Enabled) {
			t.Fatal("unselected site draft entered snapshot")
		}
		if s.ID == a.ID && s.Config.Enabled {
			t.Fatal("disabled draft lost")
		}
	}
	body, _ := json.Marshal(v)
	if strings.Contains(string(body), b.ID) || strings.Contains(string(body), "private-b") || strings.Contains(string(body), "snapshot") {
		t.Fatalf("private snapshot leaked: %s", body)
	}
	result, e := f.pub.Publish(context.Background(), f.publisher, v.ID)
	if e != nil || result != v.ID {
		t.Fatal(result, e)
	}
	current, e := f.in.Site(context.Background(), ia(f.admin), a.ID)
	if e != nil || current.PublishedRevision != 1 || !current.Published.Enabled {
		t.Fatal("queue changed effective heads", current, e)
	}
	version, e := f.pub.Version(context.Background(), f.publisher, v.ID)
	if e != nil || version.State != dd.Queued || version.Effective {
		t.Fatal("queue marked effective", version, e)
	}
}
func TestSharedTargetRequiresCompleteClosureAndPermissions(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a, b, c := f.site(t, "a"), f.site(t, "b"), f.site(t, "draft-only")
	a = f.ref(t, a, target)
	b = f.ref(t, b, target)
	f.ref(t, c, target)
	f.publishedSite(t, a)
	f.publishedSite(t, b)
	b.Draft.Maintenance.Enabled = true
	b = f.save(t, b)
	target.Config.Name = "changed"
	var e error
	target, e = f.in.SaveTarget(context.Background(), ia(f.admin), target, target.Revision)
	if e != nil {
		t.Fatal(e)
	}
	expected := selected(a)
	expected["target:"+target.ID] = target.Revision
	f.grant(t, f.publisher, a.ID)
	if _, e = f.pub.Prepare(context.Background(), f.publisher, []string{a.ID}, expected); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("missing closure permission accepted", e)
	}
	f.grant(t, f.publisher, b.ID)
	if _, e = f.pub.Prepare(context.Background(), f.publisher, []string{a.ID}, expected); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("new draft reference escaped authority", e)
	}
	f.grant(t, f.publisher, c.ID)
	v := f.prepare(t, f.publisher, []string{a.ID}, expected)
	snapshot := f.candidate(t, v.ID).Snapshot
	if len(snapshot.Sites) != 2 || len(v.AffectedSiteIDs) != 2 {
		t.Fatal("wrong actual closure", snapshot, v)
	}
	for _, s := range snapshot.Sites {
		if s.ID == b.ID && (s.Revision != 2 || s.Config.Maintenance.Enabled) {
			t.Fatal("shared closure published draft B")
		}
		if s.ID == c.ID {
			t.Fatal("draft-only new site auto-published")
		}
	}
	if snapshot.Targets[0].Revision != target.Revision {
		t.Fatal("selected target missing")
	}
}
func TestUnselectedTargetDraftAndMaterialsStayOut(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a := f.ref(t, f.site(t, "a"), target)
	f.publishedSite(t, a)
	trust, _ := f.ids.NewID()
	target.Config.Protocol = "https"
	target.Config.TLSNameMode = "fixed"
	target.Config.TLSName = "up.internal"
	target.Config.Trust = &id.MaterialRef{ID: trust, Revision: 1, Status: "unavailable"}
	if _, e := f.in.SaveTarget(context.Background(), ia(f.admin), target, target.Revision); e != nil {
		t.Fatal(e)
	}
	f.grant(t, f.publisher, a.ID)
	v := f.prepare(t, f.publisher, []string{a.ID}, selected(a))
	snap := f.candidate(t, v.ID).Snapshot
	if snap.Targets[0].Revision != 1 || snap.Targets[0].Config.Protocol != "http" || len(f.materials.seen) != 0 {
		t.Fatal("unselected target draft/material selected", snap, f.materials.seen)
	}
}
func TestMissingPublishedDependencyRequiresSelection(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	a := f.ref(t, f.site(t, "a"), target)
	if _, e := f.pub.Prepare(context.Background(), f.admin, []string{a.ID}, selected(a)); !errors.Is(e, dd.ErrInvalid) {
		t.Fatal(e)
	}
	expected := selected(a)
	expected["target:"+target.ID] = target.Revision
	f.prepare(t, f.admin, []string{a.ID}, expected)
}
func TestPublisherAWithUnrelatedPublishedBHTTPSTrust(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	target := f.target(t)
	trust, _ := f.ids.NewID()
	target.Config.Protocol = "https"
	target.Config.TLSNameMode = "fixed"
	target.Config.TLSName = "b-secret.internal"
	target.Config.Trust = &id.MaterialRef{ID: trust, Revision: 1, Status: "unavailable"}
	var e error
	target, e = f.in.SaveTarget(context.Background(), ia(f.admin), target, target.Revision)
	if e != nil {
		t.Fatal(e)
	}
	f.publishedTarget(t, target)
	b := f.ref(t, f.site(t, "private-b"), target)
	f.publishedSite(t, b)
	f.grant(t, f.publisher, a.ID)
	v := f.prepare(t, f.publisher, []string{a.ID}, selected(a))
	if len(f.materials.seen) != 1 || f.materials.seen[0].ID != trust {
		t.Fatal("complete snapshot security check absent", f.materials.seen)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), b.ID) || strings.Contains(string(raw), trust) || strings.Contains(string(raw), "b-secret") {
		t.Fatal("unrelated config leaked")
	}
	unavailable := f.coordinator(pub.UnavailableMaterials{}, jobs.New(f.p), audit.New())
	if _, e = unavailable.Prepare(context.Background(), f.publisher, []string{a.ID}, selected(a)); !errors.Is(e, dd.ErrUnavailable) {
		t.Fatal("production invented TLS readiness", e)
	}
}
func TestPublicationKeepsTokenRestrictionsAndRechecksRevocation(t *testing.T) {
	f := setup(t)
	a, b := f.site(t, "a"), f.site(t, "b")
	f.grant(t, f.publisher, a.ID)
	f.grant(t, f.publisher, b.ID)
	token, _ := f.ids.NewID()
	f.exec(t, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['publish'],$3,now()+interval '1 hour')`, token, f.publisher.UserID, []string{a.ID})
	actor := f.publisher
	actor.CredentialKind = "token"
	actor.CredentialID = token
	if _, e := f.pub.Prepare(context.Background(), actor, []string{b.ID}, selected(b)); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("token expanded to account authority", e)
	}
	v := f.prepare(t, actor, []string{a.ID}, selected(a))
	f.exec(t, `UPDATE identity_tokens SET revoked=true WHERE id=$1`, token)
	if _, e := f.pub.Publish(context.Background(), actor, v.ID); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("revoked token published", e)
	}
	if f.count(t, "deployment_releases") != 0 || f.count(t, "jobs") != 0 {
		t.Fatal("revoked publish committed")
	}
}
func TestStaleCandidateRejected(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	a.Draft.Maintenance.Enabled = true
	f.save(t, a)
	if _, e := f.pub.Publish(context.Background(), f.admin, v.ID); !errors.Is(e, dd.ErrConflict) {
		t.Fatal("stale candidate accepted", e)
	}
}
func TestNewUnselectedDraftReferenceReauthorizedAtPublish(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a := f.ref(t, f.site(t, "a"), target)
	f.grant(t, f.publisher, a.ID)
	v := f.prepare(t, f.publisher, []string{a.ID}, selected(a))
	f.ref(t, f.site(t, "new-private"), target)
	if _, e := f.pub.Publish(context.Background(), f.publisher, v.ID); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("new unauthorized phantom reference accepted", e)
	}
}
func TestCurrentGrantRevocationAndSessionExpiry(t *testing.T) {
	for _, change := range []string{"grant", "expired", "disabled", "auth_version"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			a := f.site(t, "a")
			f.grant(t, f.publisher, a.ID)
			v := f.prepare(t, f.publisher, []string{a.ID}, selected(a))
			switch change {
			case "grant":
				f.exec(t, `DELETE FROM identity_grants WHERE account_id=$1`, f.publisher.UserID)
			case "expired":
				f.exec(t, `UPDATE identity_sessions SET expires=now()-interval '1 second' WHERE id=$1`, f.publisher.CredentialID)
			case "disabled":
				f.exec(t, `UPDATE identity_accounts SET state='disabled' WHERE id=$1`, f.publisher.UserID)
			case "auth_version":
				f.exec(t, `UPDATE identity_accounts SET auth_version=2 WHERE id=$1`, f.publisher.UserID)
			}
			if _, e := f.pub.Publish(context.Background(), f.publisher, v.ID); !errors.Is(e, pub.ErrDenied) {
				t.Fatal(e)
			}
		})
	}
}

type failingJobs struct{}

func (failingJobs) EnqueueWithin(transaction.Scope, string, string, json.RawMessage) (string, error) {
	return "", errors.New("queue failed")
}

type failingAudit struct{}

func (failingAudit) Append(transaction.Scope, audit.Event) error { return errors.New("audit failed") }
func TestPublishRollbackOnQueueOrAuditFailure(t *testing.T) {
	for _, what := range []string{"jobs", "audit"} {
		t.Run(what, func(t *testing.T) {
			f := setup(t)
			a := f.site(t, "a")
			v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
			var j pub.Jobs = jobs.New(f.p)
			var auditWriter pub.Audit = audit.New()
			if what == "jobs" {
				j = failingJobs{}
			} else {
				auditWriter = failingAudit{}
			}
			s := f.coordinator(f.materials, j, auditWriter)
			before := f.count(t, "audit")
			if _, e := s.Publish(context.Background(), f.admin, v.ID); e == nil {
				t.Fatal("failure hidden")
			}
			if f.count(t, "deployment_releases") != 0 || f.count(t, "jobs") != 0 || f.count(t, "audit") != before {
				t.Fatal("transaction partially committed")
			}
		})
	}
}
func TestIdempotentPublishRacesQueueAtMostOnce(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	s := f.coordinator(pub.UnavailableMaterials{}, jobs.New(f.p), audit.New())
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, e := s.Publish(context.Background(), f.admin, v.ID)
			if e == nil && id != v.ID {
				e = fmt.Errorf("missing release id")
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if f.count(t, "deployment_releases") != 1 || f.count(t, "jobs") != 1 {
		t.Fatal("duplicate queue")
	}
	var n int
	if e := f.p.QueryRow(context.Background(), `SELECT count(*) FROM audit WHERE action='deployment.release.queued'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("duplicate audit", n, e)
	}
}
func TestSecurityMaterialRecheckedAndSafeFailure(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.materials.fail = true
	if _, e := f.pub.Publish(context.Background(), f.admin, v.ID); e != dd.ErrUnavailable || strings.Contains(e.Error(), "private") {
		t.Fatal("unsafe or skipped security failure", e)
	}
	if f.count(t, "deployment_releases") != 0 {
		t.Fatal("unavailable materials queued")
	}
}
func TestCandidateImmutableInDatabase(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	if _, e := f.p.Exec(context.Background(), `UPDATE deployment_candidates SET body='{}' WHERE id=$1`, v.ID); e == nil {
		t.Fatal("candidate mutable")
	}
	if _, e := f.p.Exec(context.Background(), `DELETE FROM deployment_candidates WHERE id=$1`, v.ID); e == nil {
		t.Fatal("candidate deletable")
	}
}
func TestPublishHoldsIdentityAndReferenceWatermarks(t *testing.T) {
	for _, mutation := range []string{"revoke", "new_reference"} {
		t.Run(mutation, func(t *testing.T) {
			f := setup(t)
			target := f.target(t)
			f.publishedTarget(t, target)
			a := f.ref(t, f.site(t, "a"), target)
			b := f.site(t, "b")
			f.grant(t, f.publisher, a.ID)
			v := f.prepare(t, f.publisher, []string{a.ID}, selected(a))
			entered, releaseGate := make(chan struct{}), make(chan struct{})
			f.materials.hook = func() { close(entered); <-releaseGate }
			pubDone := make(chan error, 1)
			go func() { _, e := f.pub.Publish(context.Background(), f.publisher, v.ID); pubDone <- e }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("publish barrier timeout")
			}
			mutDone := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if mutation == "revoke" {
					mutDone <- f.tx.Within(ctx, func(sc transaction.Scope) error {
						if e := identitypg.New().Lock(sc); e != nil {
							return e
						}
						return identitypg.New().ReplaceGrants(sc, f.publisher.UserID, nil)
					})
					return
				}
				cfg := b.Draft
				cfg.DefaultTarget = id.TargetRef{ID: target.ID}
				_, e := f.in.SaveDraft(ctx, ia(f.admin), ingress.Draft{SiteID: b.ID, Config: cfg}, b.Revision)
				mutDone <- e
			}()
			select {
			case e := <-mutDone:
				close(releaseGate)
				t.Fatalf("mutation escaped publish watermarks: %v", e)
			case <-time.After(100 * time.Millisecond):
			}
			close(releaseGate)
			if e := <-pubDone; e != nil {
				t.Fatal(e)
			}
			if e := <-mutDone; e != nil {
				t.Fatal(e)
			}
			f.materials.hook = nil
			if _, e := f.pub.Publish(context.Background(), f.publisher, v.ID); !errors.Is(e, pub.ErrDenied) {
				t.Fatal("later request ignored committed authority/reference change", e)
			}
		})
	}
}

var _ = identity.Publish

func (f *fixture) verifiedFixture(t *testing.T, v pub.CandidateView) {
	t.Helper()
	if _, e := f.pub.Publish(context.Background(), f.admin, v.ID); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE deployment_releases SET state='succeeded' WHERE id=$1`, v.ID)
}
func TestHistoricalPrepareNewCandidateUsesLogicalSourceAndCurrentGroups(t *testing.T) {
	f := setup(t)
	a, b := f.site(t, "history-a"), f.site(t, "history-b")
	f.publishedSite(t, a)
	f.publishedSite(t, b)
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.verifiedFixture(t, source)
	a.Draft.Enabled = false
	a = f.save(t, a)
	f.publishedSite(t, a)
	b.Draft.Maintenance.Enabled = true
	b = f.save(t, b)
	group, e := f.in.SaveGroup(context.Background(), ia(f.admin), id.SiteGroup{Name: "current-group"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.in.SetGroups(context.Background(), ia(f.admin), a.ID, []string{group.ID}, a.Revision); e != nil {
		t.Fatal(e)
	}
	a.Revision++
	f.exec(t, `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'group',$2)`, f.publisher.UserID, group.ID)
	historical, e := f.pub.PrepareHistorical(context.Background(), f.publisher, source.ID, []string{a.ID}, selected(a))
	if e != nil {
		t.Fatal(e)
	}
	if historical.ID == source.ID {
		t.Fatal("old artifact reused")
	}
	candidate := f.candidate(t, historical.ID)
	if candidate.Snapshot.SourceReleaseID != source.ID {
		t.Fatal("source provenance missing")
	}
	for _, s := range candidate.Snapshot.Sites {
		if s.ID == a.ID && (!s.Config.Enabled || s.Revision != 1) {
			t.Fatal("old logical version missing", s)
		}
		if s.ID == b.ID && (s.Revision != 1 || s.Config.Maintenance.Enabled) {
			t.Fatal("unselected draft restored", s)
		}
	}
	if _, e = f.pub.Publish(context.Background(), f.publisher, historical.ID); e != nil {
		t.Fatal(e)
	}
	current, e := f.in.Site(context.Background(), ia(f.admin), a.ID)
	if e != nil || current.Draft.Enabled || current.Published.Enabled || len(current.GroupIDs) != 1 || current.GroupIDs[0] != group.ID {
		t.Fatal("history changed heads/group", current, e)
	}
}
func TestHistoricalRequiresVerifiedSourceAndCurrentGuards(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	if _, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a)); !errors.Is(e, dd.ErrInvalid) {
		t.Fatal("unverified source used", e)
	}
	f.verifiedFixture(t, source)
	a.Draft.Enabled = false
	a = f.save(t, a)
	if _, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, map[string]int64{"site:" + a.ID: 1}); !errors.Is(e, dd.ErrConflict) {
		t.Fatal("historical guard stale", e)
	}
}
func TestHistoricalCurrentSharedClosureAndRetiredMaterials(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a := f.ref(t, f.site(t, "a"), target)
	f.publishedSite(t, a)
	expected := selected(a)
	expected["target:"+target.ID] = target.Revision
	source := f.prepare(t, f.admin, []string{a.ID}, expected)
	f.verifiedFixture(t, source)
	f.grant(t, f.publisher, a.ID)
	b := f.ref(t, f.site(t, "new-private"), target)
	if _, e := f.pub.PrepareHistorical(context.Background(), f.publisher, source.ID, []string{a.ID}, expected); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("current draft reference ignored", e)
	}
	f.grant(t, f.publisher, b.ID)
	historical, e := f.pub.PrepareHistorical(context.Background(), f.publisher, source.ID, []string{a.ID}, expected)
	if e != nil {
		t.Fatal(e)
	}
	f.materials.fail = true
	if _, e = f.pub.Publish(context.Background(), f.publisher, historical.ID); !errors.Is(e, dd.ErrUnavailable) {
		t.Fatal("retired current binding restored", e)
	}
	if _, e = f.pub.PrepareHistorical(context.Background(), f.publisher, source.ID, []string{a.ID}, expected); !errors.Is(e, dd.ErrUnavailable) {
		t.Fatal("retired material prepared", e)
	}
}
func TestHistoricalSoftDeletedSiteCannotRevive(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.verifiedFixture(t, source)
	if e := f.in.DeleteSite(context.Background(), ia(f.admin), a.ID, a.Revision); e != nil {
		t.Fatal(e)
	}
	if _, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a)); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("deleted site revived", e)
	}
}
func TestHistoricalDomainCannotReclaimAnotherUnselectedDraft(t *testing.T) {
	f := setup(t)
	a := f.site(t, "old-a")
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.verifiedFixture(t, source)
	oldDomain := a.Draft.Domains[0]
	a.Draft.Domains = []string{"new-a.example.test"}
	a = f.save(t, a)
	f.publishedSite(t, a)
	historical, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a))
	if e != nil {
		t.Fatal(e)
	}
	// Explicit owned effective-state fixture updates only the old domain claim;
	// queued publication itself never writes claims or published heads.
	f.exec(t, `DELETE FROM ingress_domains WHERE domain=$1`, oldDomain)
	b := f.site(t, "new-b")
	b.Draft.Domains = []string{oldDomain}
	f.save(t, b)
	if _, e = f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a)); !errors.Is(e, dd.ErrConflict) {
		t.Fatal("history stole current draft domain", e)
	}
	if _, e = f.pub.Publish(context.Background(), f.admin, historical.ID); !errors.Is(e, dd.ErrConflict) {
		t.Fatal("publish ignored changed domain claims", e)
	}
}

func TestHistoricalCurrentMaterialCompatibilityFailsClosed(t *testing.T) {
	for _, state := range []string{"disabled", "revoked", "expired", "name_mismatch", "purpose_mismatch"} {
		t.Run(state, func(t *testing.T) {
			f := setup(t)
			a := f.site(t, "tls-a")
			certificate, _ := f.ids.NewID()
			a.Draft.EntryCertificate = &id.MaterialRef{ID: certificate, Revision: 1, Status: "unavailable"}
			a = f.save(t, a)
			source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
			f.verifiedFixture(t, source)
			// Test-owned current binding adapter: I2 verifies it receives the exact
			// logical certificate, requested hostname and purpose. P5 owns real X.509.
			bad := false
			f.materials.historicalCheck = func(reqs []deploy.MaterialRequirement) error {
				found := false
				for _, r := range reqs {
					if r.Ref.ID == certificate {
						found = true
						if r.Ref.Revision != 1 || r.Usage != "serverAuth" || len(r.Names) != 1 || r.Names[0] != "tls-a.example.test" {
							return errors.New("wrong binding requirements")
						}
					}
				}
				if !found {
					return errors.New("certificate requirements omitted")
				}
				if bad {
					return fmt.Errorf("current binding %s", state)
				}
				return nil
			}
			v, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a))
			if e != nil {
				t.Fatal(e)
			}
			bad = true
			if _, e = f.pub.Publish(context.Background(), f.admin, v.ID); !errors.Is(e, dd.ErrUnavailable) {
				t.Fatal("retired binding published", e)
			}
			if _, e = f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a)); !errors.Is(e, dd.ErrUnavailable) {
				t.Fatal("retired binding prepared", e)
			}
			unavailable := f.coordinator(pub.UnavailableMaterials{}, jobs.New(f.p), audit.New())
			if _, e = unavailable.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a)); !errors.Is(e, dd.ErrUnavailable) {
				t.Fatal("missing P5 fabricated historical binding", e)
			}
		})
	}
}
func TestHistoricalTargetSelectionPreservesCurrentPublishedUnlessExplicit(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a, b := f.ref(t, f.site(t, "a"), target), f.ref(t, f.site(t, "b"), target)
	f.publishedSite(t, a)
	f.publishedSite(t, b)
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.verifiedFixture(t, source)
	target.Config.Name = "current"
	var e error
	target, e = f.in.SaveTarget(context.Background(), ia(f.admin), target, target.Revision)
	if e != nil {
		t.Fatal(e)
	}
	f.publishedTarget(t, target)
	v, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a))
	if e != nil {
		t.Fatal(e)
	}
	if f.candidate(t, v.ID).Snapshot.Targets[0].Revision != 2 {
		t.Fatal("unselected old target restored")
	}
	expected := selected(a)
	expected["target:"+target.ID] = 2
	v, e = f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, expected)
	if e != nil {
		t.Fatal(e)
	}
	if c := f.candidate(t, v.ID); c.Snapshot.Targets[0].Revision != 1 || len(c.AffectedSiteIDs) != 2 {
		t.Fatal("explicit old shared target not restored", c)
	}
}
func TestHistoricalDeletedTargetCannotRevive(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	a := f.ref(t, f.site(t, "a"), target)
	expected := selected(a)
	expected["target:"+target.ID] = target.Revision
	source := f.prepare(t, f.admin, []string{a.ID}, expected)
	f.verifiedFixture(t, source)
	a.Draft.DefaultTarget = id.TargetRef{}
	a = f.save(t, a)
	if e := f.in.DeleteTarget(context.Background(), ia(f.admin), target.ID, target.Revision); e != nil {
		t.Fatal(e)
	}
	expected = selected(a)
	expected["target:"+target.ID] = target.Revision
	if _, e := f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, expected); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("deleted target revived", e)
	}
}

func TestPublishedBaseChangeStalesFullCandidate(t *testing.T) {
	f := setup(t)
	a, b := f.site(t, "a"), f.site(t, "b")
	f.publishedSite(t, b)
	v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	b.Draft.Enabled = false
	b = f.save(t, b)
	f.publishedSite(t, b)
	if _, e := f.pub.Publish(context.Background(), f.admin, v.ID); !errors.Is(e, dd.ErrConflict) {
		t.Fatal("changed published base overwritten", e)
	}
}
func TestUnusedDraftChangeDoesNotStaleCandidate(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a := f.ref(t, f.site(t, "a"), target)
	b := f.site(t, "b")
	f.publishedSite(t, b)
	v := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	target.Config.Name = "not-selected"
	if _, e := f.in.SaveTarget(context.Background(), ia(f.admin), target, target.Revision); e != nil {
		t.Fatal(e)
	}
	b.Draft.Maintenance.Enabled = true
	f.save(t, b)
	if _, e := f.pub.Publish(context.Background(), f.admin, v.ID); e != nil {
		t.Fatal("unused draft staled candidate", e)
	}
}
func TestHistoricalPublishRechecksNewDraftReference(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a := f.ref(t, f.site(t, "a"), target)
	f.publishedSite(t, a)
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.verifiedFixture(t, source)
	f.grant(t, f.publisher, a.ID)
	v, e := f.pub.PrepareHistorical(context.Background(), f.publisher, source.ID, []string{a.ID}, selected(a))
	if e != nil {
		t.Fatal(e)
	}
	f.ref(t, f.site(t, "new-private"), target)
	if _, e = f.pub.Publish(context.Background(), f.publisher, v.ID); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("historical publish lost current reference ACL", e)
	}
}

// A selected draft replaces its old published content in the final snapshot.
// That must not erase the independent optimistic guard on the published base.
func TestSelectedPublishedBaseHeadChangesStaleCandidate(t *testing.T) {
	for _, resource := range []string{"site", "shared_target", "historical_site"} {
		t.Run(resource, func(t *testing.T) {
			f := setup(t)
			a := f.site(t, "selected-a")
			if resource == "shared_target" {
				target := f.target(t)
				f.publishedTarget(t, target)
				a = f.ref(t, a, target)
				b := f.ref(t, f.site(t, "shared-b"), target)
				f.publishedSite(t, a)
				f.publishedSite(t, b)
				target.Config.Name = "next-target"
				var e error
				target, e = f.in.SaveTarget(context.Background(), ia(f.admin), target, target.Revision)
				if e != nil {
					t.Fatal(e)
				}
				expected := selected(a)
				expected["target:"+target.ID] = target.Revision
				candidate := f.prepare(t, f.admin, []string{a.ID}, expected)
				f.publishedTarget(t, target) // verified apply fixture; draft guard stays the same
				if _, e = f.pub.Publish(context.Background(), f.admin, candidate.ID); !errors.Is(e, dd.ErrConflict) {
					t.Fatalf("selected target published base changed without conflict: %v", e)
				}
				return
			}
			f.publishedSite(t, a)
			var source pub.CandidateView
			if resource == "historical_site" {
				source = f.prepare(t, f.admin, []string{a.ID}, selected(a))
				f.verifiedFixture(t, source)
			}
			a.Draft.Enabled = false
			a = f.save(t, a)
			var candidate pub.CandidateView
			if resource == "historical_site" {
				var e error
				candidate, e = f.pub.PrepareHistorical(context.Background(), f.admin, source.ID, []string{a.ID}, selected(a))
				if e != nil {
					t.Fatal(e)
				}
			} else {
				candidate = f.prepare(t, f.admin, []string{a.ID}, selected(a))
			}
			f.publishedSite(t, a) // published 1 -> 2 while draft remains exactly revision 2
			if _, e := f.pub.Publish(context.Background(), f.admin, candidate.ID); !errors.Is(e, dd.ErrConflict) {
				t.Fatalf("selected %s published base changed without conflict: %v", resource, e)
			}
		})
	}
}

func TestCompatibleCurrentMaterialRotationDoesNotStaleLogicalCandidate(t *testing.T) {
	f := setup(t)
	a := f.site(t, "rotation-a")
	certificate, _ := f.ids.NewID()
	a.Draft.EntryCertificate = &id.MaterialRef{ID: certificate, Revision: 1, Status: "unavailable"}
	a = f.save(t, a)
	f.publishedSite(t, a)
	currentVersion := 1
	eligible := map[int]bool{1: true}
	// The test-owned provider resolves a current runtime version from a fixed
	// logical spec. Rotating that version must not alter the logical base guard.
	f.materials.currentCheck = func(refs []deploy.Material) error {
		if len(refs) != 1 || refs[0].ID != certificate || refs[0].Revision != 1 {
			return errors.New("logical material reference changed")
		}
		if !eligible[currentVersion] {
			return errors.New("no eligible current version")
		}
		return nil
	}
	candidate := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	eligible[1] = false
	currentVersion = 2
	eligible[2] = true
	if _, e := f.pub.Publish(context.Background(), f.admin, candidate.ID); e != nil {
		t.Fatal("compatible runtime material rotation staled logical configuration", e)
	}
	if saved := f.candidate(t, candidate.ID); saved.PublishedBase["site:"+a.ID] != a.Revision || saved.Snapshot.Sites[0].Config.EntryCertificate.Revision != 1 {
		t.Fatal("published base or logical spec lost", saved)
	}
}
func TestVersionReadsRecheckCurrentViewScopeAndCredential(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	f.publishedTarget(t, target)
	a := f.ref(t, f.site(t, "a"), target)
	candidate := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	readonly := f.actor(t, "readonly")
	f.grant(t, readonly, a.ID)
	if _, e := f.pub.Version(context.Background(), readonly, candidate.ID); e != nil {
		t.Fatal(e)
	}
	b := f.ref(t, f.site(t, "private-new-ref"), target)
	if _, e := f.pub.Version(context.Background(), readonly, candidate.ID); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("view ignored new private draft reference", e)
	}
	f.grant(t, readonly, b.ID)
	token, _ := f.ids.NewID()
	f.exec(t, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['view'],$3,now()+interval '1 hour')`, token, readonly.UserID, []string{a.ID, b.ID})
	reader := readonly
	reader.CredentialKind = "token"
	reader.CredentialID = token
	if _, e := f.pub.Version(context.Background(), reader, candidate.ID); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE identity_tokens SET revoked=true WHERE id=$1`, token)
	if _, e := f.pub.Version(context.Background(), reader, candidate.ID); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("revoked view token read release", e)
	}
}
func TestHistoricalPreparationStillRequiresPublishAction(t *testing.T) {
	f := setup(t)
	a := f.site(t, "a")
	source := f.prepare(t, f.admin, []string{a.ID}, selected(a))
	f.verifiedFixture(t, source)
	readonly := f.actor(t, "readonly")
	f.grant(t, readonly, a.ID)
	if _, e := f.pub.PrepareHistorical(context.Background(), readonly, source.ID, []string{a.ID}, selected(a)); !errors.Is(e, pub.ErrDenied) {
		t.Fatal("view role prepared historical publish", e)
	}
}

func TestRouteRateRoundTripIntoImmutableCandidate(t *testing.T) {
	f := setup(t)
	target := f.target(t)
	site := f.site(t, "route-rate")
	site.Draft.DefaultTarget = id.TargetRef{ID: target.ID}
	site.Draft.Routes = []id.Route{{Match: "prefix", Path: "/limited/", Target: id.TargetRef{ID: target.ID}, Rate: &id.RatePolicy{RequestsPerSecond: 2, Connections: 1}}}
	site = f.save(t, site)
	v := f.prepare(t, f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision, "target:" + target.ID: target.Revision})
	candidate := f.candidate(t, v.ID)
	rate := candidate.Snapshot.Sites[0].Config.Routes[0].Rate
	if rate == nil || rate.RequestsPerSecond != 2 || rate.Connections != 1 {
		t.Fatalf("route cap lost through PostgreSQL/export/mapping: %+v", rate)
	}
}

func TestFirstQueuedPublisherProvenanceIsImmutable(t *testing.T) {
	f := setup(t)
	s := f.site(t, "provenance")
	f.grant(t, f.publisher, s.ID)
	ctx := context.Background()
	c, e := f.pub.Prepare(ctx, f.admin, []string{s.ID}, map[string]int64{"site:" + s.ID: s.Revision})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.pub.Publish(ctx, f.publisher, c.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.pub.Publish(ctx, f.admin, c.ID); e != nil {
		t.Fatal(e)
	}
	var payload []byte
	if e = f.p.QueryRow(ctx, "SELECT payload FROM jobs WHERE kind='deployment.apply' AND key=$1", c.ID).Scan(&payload); e != nil {
		t.Fatal(e)
	}
	var got struct {
		Publisher pub.ActorRef `json:"publisher"`
	}
	if e = json.Unmarshal(payload, &got); e != nil {
		t.Fatal(e)
	}
	if got.Publisher != f.publisher {
		t.Fatalf("first authenticated publisher not preserved: %+v", got.Publisher)
	}
}

type runtimeSource struct{}

func (runtimeSource) ReadWithin(transaction.Scope, deploy.Snapshot) (edge.RuntimeState, error) {
	return edge.RuntimeState{Generation: "generation-1", Now: time.Now()}, nil
}
func TestExecutorRechecksQueuedPublisherAndCommitsOwnerReceipt(t *testing.T) {
	f := setup(t)
	s := f.site(t, "execution")
	f.grant(t, f.publisher, s.ID)
	ctx := context.Background()
	c, e := f.pub.Prepare(ctx, f.admin, []string{s.ID}, map[string]int64{"site:" + s.ID: s.Revision})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.pub.Publish(ctx, f.publisher, c.ID); e != nil {
		t.Fatal(e)
	}
	jobs := jobs.New(f.p)
	j, e := jobs.ClaimKinds(ctx, "edge", time.Minute, []string{"deployment.apply"})
	if e != nil {
		t.Fatal(e)
	}
	ex := pub.NewExecution(f.pub, jobs, j, runtimeSource{}, nginx.Compiler{})
	plan, e := ex.Prepare(ctx, c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = ex.ActivateWithin(ctx, c.ID, plan, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	var prematurelyPublished bool
	if e = f.p.QueryRow(ctx, "SELECT published_revision IS NOT NULL FROM ingress_sites WHERE id=$1", s.ID).Scan(&prematurelyPublished); e != nil || prematurelyPublished {
		t.Fatal("activation prematurely published heads", e)
	}
	var activationState string
	if e = f.p.QueryRow(ctx, "SELECT state FROM deployment_releases WHERE id=$1", c.ID).Scan(&activationState); e != nil || activationState != "queued" {
		t.Fatal("activation prematurely acknowledged release", activationState, e)
	}
	called := false
	e = ex.Within(ctx, c.ID, plan, func() error { called = true; return nil })
	if e != nil || !called {
		t.Fatalf("guarded effect %v", e)
	}
	var published int64
	var state, status string
	if e = f.p.QueryRow(ctx, "SELECT published_revision FROM ingress_sites WHERE id=$1", s.ID).Scan(&published); e != nil || published != s.Revision {
		t.Fatalf("ingress owner receipt %d %v", published, e)
	}
	if e = f.p.QueryRow(ctx, "SELECT state FROM deployment_releases WHERE id=$1", c.ID).Scan(&state); e != nil || state != "succeeded" {
		t.Fatalf("release receipt %s %v", state, e)
	}
	if e = f.p.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", j.ID).Scan(&status); e != nil || status != "completed" {
		t.Fatalf("job receipt %s %v", status, e)
	}
	view, e := f.pub.Version(ctx, f.admin, c.ID)
	if e != nil || !view.Effective || view.ObservedVersion != c.ID+"/generation-1" || view.RestoredVersion != "" {
		t.Fatalf("verified query metadata: %+v %v", view, e)
	}
	// Expiration of an old human credential cannot stop current verified renewal.
	f.exec(t, "UPDATE identity_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id=$1", f.publisher.CredentialID)
	if _, e = ex.CurrentVerified(ctx); e != nil {
		t.Fatalf("recovery depends on old publisher: %v", e)
	}
}
func TestExecutorRevokedQueuedPublisherAndMidTransactionLeaseExpiry(t *testing.T) {
	for _, failure := range []string{"revoked", "lease"} {
		t.Run(failure, func(t *testing.T) {
			f := setup(t)
			s := f.site(t, "execution-denied")
			f.grant(t, f.publisher, s.ID)
			ctx := context.Background()
			c, e := f.pub.Prepare(ctx, f.admin, []string{s.ID}, map[string]int64{"site:" + s.ID: s.Revision})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.pub.Publish(ctx, f.publisher, c.ID); e != nil {
				t.Fatal(e)
			}
			store := jobs.New(f.p)
			j, e := store.ClaimKinds(ctx, "edge", time.Minute, []string{"deployment.apply"})
			if e != nil {
				t.Fatal(e)
			}
			var active transaction.Scope
			runner := capturedTransactionRunner{Runner: postgres.NewRunner(f.p), active: &active}
			coordinator := pub.New(runner, f.access, f.in, f.materials, f.releases, store, audit.New(), f.ids)
			ex := pub.NewExecution(coordinator, store, j, runtimeSource{}, nginx.Compiler{})
			plan, e := ex.Prepare(ctx, c.ID)
			if e != nil {
				t.Fatal(e)
			}
			if e = ex.ActivateWithin(ctx, c.ID, plan, func() error { return nil }); e != nil {
				t.Fatal(e)
			}
			if failure == "revoked" {
				f.exec(t, "UPDATE identity_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id=$1", f.publisher.CredentialID)
			}
			called := false
			e = ex.Within(ctx, c.ID, plan, func() error {
				called = true
				if failure == "lease" {
					// Arm the original fault window at the intended transaction
					// phase, after setup and initial fencing, using its held row.
					if err := postgres.Use(active, func(ctx context.Context, tx pgx.Tx) error {
						changed, err := tx.Exec(ctx, `UPDATE jobs SET deadline=clock_timestamp()+interval '300 milliseconds' WHERE id=$1 AND lease_token=$2 AND status='running'`, j.ID, j.LeaseToken)
						if err == nil && changed.RowsAffected() != 1 {
							return errors.New("owned lease was not armed")
						}
						return err
					}); err != nil {
						return err
					}
					time.Sleep(350 * time.Millisecond)
				}
				return nil
			})
			if e == nil {
				t.Fatal("invalid authority committed")
			}
			if failure == "lease" && (!called || !errors.Is(e, jobs.ErrLeaseLost)) {
				t.Fatal("mid-transaction lease expiry was not exercised", called, e)
			}
			if failure == "revoked" && called {
				t.Fatal("revoked queued publisher reached native effect")
			}
			var state string
			var published int64
			if e = f.p.QueryRow(ctx, "SELECT coalesce(published_revision,0) FROM ingress_sites WHERE id=$1", s.ID).Scan(&published); e != nil || published != 0 {
				t.Fatalf("unfenced head advanced: %d %v", published, e)
			}
			if e = f.p.QueryRow(ctx, "SELECT state FROM deployment_releases WHERE id=$1", c.ID).Scan(&state); e != nil || state != "queued" {
				t.Fatalf("failed tx receipt: %s %v", state, e)
			}
		})
	}
}

type changingRuntimeSource struct {
	generation  string
	unavailable bool
}

func (s *changingRuntimeSource) ReadWithin(transaction.Scope, deploy.Snapshot) (edge.RuntimeState, error) {
	if s.unavailable {
		return edge.RuntimeState{}, dd.ErrUnavailable
	}
	return edge.RuntimeState{Generation: s.generation, Now: time.Now()}, nil
}
func TestFinalAuthorityRechecksStagedSecurityGeneration(t *testing.T) {
	f := setup(t)
	site := f.site(t, "generation-guard")
	ctx := context.Background()
	c, e := f.pub.Prepare(ctx, f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.pub.Publish(ctx, f.admin, c.ID); e != nil {
		t.Fatal(e)
	}
	store := jobs.New(f.p)
	job, e := store.ClaimKinds(ctx, "edge", time.Minute, []string{"deployment.apply"})
	if e != nil {
		t.Fatal(e)
	}
	source := &changingRuntimeSource{generation: "g1"}
	ex := pub.NewExecution(f.pub, store, job, source, nginx.Compiler{})
	plan, e := ex.Prepare(ctx, c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = ex.ActivateWithin(ctx, c.ID, plan, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	source.generation = "g2"
	called := false
	e = ex.Within(ctx, c.ID, plan, func() error { called = true; return nil })
	if e == nil || called {
		t.Fatalf("stale staged security reached effect: %v", e)
	}
}
func TestDerivedGenerationUsesVerifiedConfigAndSameScopeLease(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			f := setup(t)
			site := f.site(t, "derived")
			ctx := context.Background()
			c, e := f.pub.Prepare(ctx, f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.pub.Publish(ctx, f.admin, c.ID); e != nil {
				t.Fatal(e)
			}
			store := jobs.New(f.p)
			job, e := store.ClaimKinds(ctx, "edge", time.Minute, []string{"deployment.apply"})
			if e != nil {
				t.Fatal(e)
			}
			source := &changingRuntimeSource{generation: "g1"}
			ex := pub.NewExecution(f.pub, store, job, source, nginx.Compiler{})
			plan, e := ex.Prepare(ctx, c.ID)
			if e != nil {
				t.Fatal(e)
			}
			if e = ex.Within(ctx, c.ID, plan, func() error { return nil }); e != nil {
				t.Fatal(e)
			}
			site.Draft.Maintenance = id.MaintenancePolicy{Enabled: true, Status: 503, Message: "unpublished"}
			site = f.save(t, site)
			f.exec(t, "UPDATE identity_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id=$1", f.admin.CredentialID)
			if _, e = store.Enqueue(ctx, "deployment.generation", "renew", json.RawMessage(`{"kind":"certificate"}`)); e != nil {
				t.Fatal(e)
			}
			lease := time.Minute
			if expired {
				lease = 300 * time.Millisecond
			}
			job, e = store.ClaimKinds(ctx, "edge", lease, []string{"deployment.generation"})
			if e != nil {
				t.Fatal(e)
			}
			source.generation = "g2"
			ex = pub.NewExecution(f.pub, store, job, source, nginx.Compiler{})
			plan, e = ex.CurrentVerified(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if plan.Snapshot.Sites[0].Config.Maintenance.Enabled {
				t.Fatal("system generation picked a draft")
			}
			e = ex.WithRestore(ctx, plan, func(context.Context) error {
				if expired {
					time.Sleep(350 * time.Millisecond)
				}
				return nil
			})
			if expired && e == nil || !expired && e != nil {
				t.Fatalf("generation lease expiry=%v error=%v", expired, e)
			}
			var version, status string
			if e = f.p.QueryRow(ctx, "SELECT version FROM deployment_runtime").Scan(&version); e != nil {
				t.Fatal(e)
			}
			if e = f.p.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", job.ID).Scan(&status); e != nil {
				t.Fatal(e)
			}
			if expired && (version != c.ID+"/g1" || status != "running") || !expired && (version != c.ID+"/g2" || status != "completed") {
				t.Fatalf("non-atomic derived receipt: %s %s", version, status)
			}
			source.unavailable = true
			called := false
			e = ex.WithRestore(ctx, plan, func(context.Context) error { called = true; return nil })
			if e == nil || called {
				t.Fatalf("restore revived unavailable security: %v", e)
			}
		})
	}
}

type preparedRuntime struct {
	runtimeSource
	prepare func(context.Context, deploy.Snapshot) error
	reads   int
}

func (s *preparedRuntime) Prepare(ctx context.Context, snapshot deploy.Snapshot) error {
	return s.prepare(ctx, snapshot)
}
func (s *preparedRuntime) ReadWithin(sc transaction.Scope, snapshot deploy.Snapshot) (edge.RuntimeState, error) {
	s.reads++
	return s.runtimeSource.ReadWithin(sc, snapshot)
}
func TestDNSPreparationEndsScopeThenRechecksPublisher(t *testing.T) {
	f := setup(t)
	site := f.site(t, "outside-dns")
	ctx := context.Background()
	c, e := f.pub.Prepare(ctx, f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.pub.Publish(ctx, f.admin, c.ID); e != nil {
		t.Fatal(e)
	}
	store := jobs.New(f.p)
	job, e := store.ClaimKinds(ctx, "edge", time.Minute, []string{"deployment.apply"})
	if e != nil {
		t.Fatal(e)
	}
	source := &preparedRuntime{prepare: func(ctx context.Context, snapshot deploy.Snapshot) error {
		if len(snapshot.Sites) != 1 || snapshot.Sites[0].ID != site.ID {
			t.Fatal("wrong immutable candidate")
		}
		// A separate transaction can revoke now. It would block on the first
		// identity watermark if network preparation retained the original Scope.
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return f.tx.Within(ctx, func(sc transaction.Scope) error { return identitypg.New().Lock(sc) })
	}}
	ex := pub.NewExecution(f.pub, store, job, source, nginx.Compiler{})
	if _, e = ex.Prepare(ctx, c.ID); e != nil || source.reads != 1 {
		t.Fatal("outside preparation", e, source.reads)
	}
	source.prepare = func(ctx context.Context, _ deploy.Snapshot) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, e := f.p.Exec(ctx, "UPDATE identity_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id=$1", f.admin.CredentialID)
		return e
	}
	if _, e = ex.Prepare(ctx, c.ID); !errors.Is(e, access.ErrDenied) {
		t.Fatal("revoked publisher passed second scope", e)
	}
	if source.reads != 1 {
		t.Fatal("runtime read after revocation", source.reads)
	}
}

func TestReleaseHistoryContinuesPastDeniedRawPages(t *testing.T) {
	f := setup(t)
	visible, hidden := f.site(t, "visible-history"), f.site(t, "hidden-history")
	f.grant(t, f.publisher, visible.ID)
	old, err := f.pub.Prepare(t.Context(), f.admin, []string{visible.ID}, map[string]int64{"site:" + visible.ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	// An older authorized succeeded release and 105 newer denied rows.
	if _, err = f.pub.Publish(t.Context(), f.admin, old.ID); err != nil {
		t.Fatal(err)
	}
	f.exec(t, "UPDATE deployment_releases SET state='succeeded' WHERE id=$1", old.ID)
	for i := range 105 {
		if i < 5 && i%2 == 0 {
			if _, err := f.pub.Prepare(t.Context(), f.admin, []string{visible.ID}, map[string]int64{"site:" + visible.ID: 1}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.pub.Prepare(t.Context(), f.admin, []string{hidden.ID}, map[string]int64{"site:" + hidden.ID: 1}); err != nil {
			t.Fatal(err)
		}
	}
	server := echo.New()
	releasehttp.Register(server, f.pub, func(*echo.Context, bool) (pub.ActorRef, error) { return f.publisher, nil })
	fetch := func(offset int) (int, struct {
		Items []pub.CandidateView `json:"items"`
		More  bool                `json:"has_more"`
		Next  *int                `json:"next_offset"`
	}) {
		w := httptest.NewRecorder()
		server.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/releases?limit=100&offset=%d", offset), nil))
		var page struct {
			Items []pub.CandidateView `json:"items"`
			More  bool                `json:"has_more"`
			Next  *int                `json:"next_offset"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return w.Code, page
	}
	code, first := fetch(0)
	if code != 200 || len(first.Items) != 0 || !first.More || first.Next == nil || *first.Next != 100 {
		t.Fatalf("denied first page truncated authorized history: code=%d page=%+v", code, first)
	}
	code, last := fetch(*first.Next)
	if code != 200 || len(last.Items) != 4 || last.Items[3].ID != old.ID || last.Items[3].State != dd.Succeeded || last.More || last.Next != nil {
		t.Fatalf("older authorized history missing or denied metadata disclosed: %d %+v", code, last)
	}
	for _, v := range last.Items {
		for _, site := range v.AffectedSiteIDs {
			if site != visible.ID {
				t.Fatal("denied metadata leaked", v)
			}
		}
	}
	for _, offset := range []int{-1, 100001} {
		if code, _ := fetch(offset); code != 400 {
			t.Fatal("unbounded history accepted", offset, code)
		}
	}
	f.exec(t, "UPDATE identity_sessions SET revoked=true WHERE id=$1", f.publisher.CredentialID)
	if code, _ := fetch(100); code != 403 {
		t.Fatalf("revoked credential continued history: %d", code)
	}
}
