//go:build integration

package composition

import (
	"context"
	"errors"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	identitypg "gatebeam/internal/modules/identity/infrastructure/postgres"
	"gatebeam/internal/modules/ingress"
	app "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	ingresspg "gatebeam/internal/modules/ingress/infrastructure/postgres"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
	"time"
)

func TestStatisticsCurrentCredentialMembershipAndFences(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	ids := credential.New()
	catalog := &ingressaccess.Catalog{}
	auth := identity.NewAccess(p, catalog)
	in := ingress.New(p, ingressaccess.Authorizer{Identity: auth})
	catalog.Ingress = in
	actor := func(role string) app.ActorRef {
		u, _ := ids.NewID()
		c, _ := ids.NewID()
		if _, e := p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01',$2)`, u, role); e != nil {
			t.Fatal(e)
		}
		if _, e := p.Exec(ctx, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$1,$1,1,now()+interval '1 hour')`, c, u); e != nil {
			t.Fatal(e)
		}
		return app.ActorRef{UserID: u, CredentialKind: "session", CredentialID: c, AuthVersion: 1}
	}
	admin := actor("admin")
	reader := actor("readonly")
	group, e := in.SaveGroup(ctx, admin, domain.SiteGroup{Name: "logs"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	site, e := in.CreateSite(ctx, admin, app.CreateSite{Name: "observed", GroupIDs: []string{group.ID}, Config: domain.SiteConfig{Enabled: true, Domains: []string{"observed.example.test"}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'group',$2)`, reader.UserID, group.ID); e != nil {
		t.Fatal(e)
	}
	tid, _ := ids.NewID()
	if _, e = p.Exec(ctx, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['view'],ARRAY[$3],now()+interval '1 hour')`, tid, reader.UserID, site.ID); e != nil {
		t.Fatal(e)
	}
	query := NewStatistics(p)
	a := stats.ActorRef{UserID: reader.UserID, AuthVersion: 1, CredentialKind: "token", CredentialID: tid}
	from := time.Now().UTC().Truncate(time.Hour)
	filter := stats.Filter{SiteIDs: []string{site.ID}, From: from, To: from.Add(time.Hour)}
	check := func(want bool) {
		t.Helper()
		_, e := query.Query(ctx, a, filter)
		if want && e != nil {
			t.Fatal(e)
		}
		if !want && !errors.Is(e, stats.ErrDenied) {
			t.Fatalf("expected denial, got %v", e)
		}
	}
	check(true)
	// Same Scope contains the current permission locks and actual stats query.
	tx := postgres.NewRunner(p)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- tx.Within(ctx, func(sc transaction.Scope) error {
			if e := identitypg.New().Lock(sc); e != nil {
				return e
			}
			close(entered)
			<-release
			_, e := p.Exec(sc.Context(), `SELECT 1`)
			return e
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("lock deadline")
	}
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, e = query.Query(bounded, a, filter)
	cancel()
	if e == nil {
		t.Fatal("query skipped identity fence")
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	entered, release = make(chan struct{}), make(chan struct{})
	go func() {
		done <- tx.Within(ctx, func(sc transaction.Scope) error {
			if e := ingresspg.New().WriteLock(sc); e != nil {
				return e
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("graph lock deadline")
	}
	bounded, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
	_, e = query.Query(bounded, a, filter)
	cancel()
	if e == nil {
		t.Fatal("query skipped graph fence")
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `UPDATE identity_tokens SET revoked=true WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	check(false)
	if _, e = p.Exec(ctx, `UPDATE identity_tokens SET revoked=false,expires=now()-interval '1 second' WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	check(false)
	a = stats.ActorRef{UserID: reader.UserID, AuthVersion: 1, CredentialKind: "session", CredentialID: reader.CredentialID}
	check(true)
	if e = in.SetGroups(ctx, admin, site.ID, nil, site.Revision); e != nil {
		t.Fatal(e)
	}
	check(false)
}
