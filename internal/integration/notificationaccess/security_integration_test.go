//go:build integration

package notificationaccess_test

import (
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/notificationaccess"
	"gatebeam/internal/modules/identity"
	identityapp "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/ingress"
	ingressapp "gatebeam/internal/modules/ingress/application"
	ingressdomain "gatebeam/internal/modules/ingress/domain"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"testing"
)

func TestPersistentOwnerCurrentRoleAndScopeNotCreatorSession(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	uid, sid := uuid.NewString(), uuid.NewString()
	if _, e := p.Exec(t.Context(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','admin')`, uid); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(t.Context(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$1,$1,1,now()+interval '1 hour')`, sid, uid); e != nil {
		t.Fatal(e)
	}
	catalog := &ingressaccess.Catalog{}
	access := identity.NewAccess(p, catalog)
	sites := ingress.New(p, ingressaccess.Authorizer{Identity: access})
	catalog.Ingress = sites
	a := ingressapp.ActorRef{UserID: uid, CredentialKind: "session", CredentialID: sid, AuthVersion: 1}
	site, e := sites.CreateSite(t.Context(), a, ingressapp.CreateSite{Name: "owned", Config: ingressdomain.SiteConfig{Enabled: true, Domains: []string{"owned.test"}}})
	if e != nil {
		t.Fatal(e)
	}
	security := &notificationaccess.Security{Access: access, Ingress: sites, Background: true}
	c := app.Channel{OwnerID: uid, SiteIDs: []string{site.ID}}
	check := func(want bool) {
		t.Helper()
		e := tx.Within(t.Context(), func(sc transaction.Scope) error {
			return security.DeliveryWithin(sc, c, app.Event{Kind: "channel_test"})
		})
		if (e == nil) != want {
			t.Fatalf("permission=%v error=%v", want, e)
		}
	}
	check(true)
	if _, e = p.Exec(t.Context(), `UPDATE identity_sessions SET expires=now()-interval '1 hour' WHERE id=$1`, sid); e != nil {
		t.Fatal(e)
	}
	check(true)
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error {
		return access.RequireWithin(sc, identityapp.Actor{UserID: uid, CredentialID: sid, CredentialKind: identityapp.SessionCredential, AuthVersion: 1}, identityapp.Manage, nil)
	}); e == nil {
		t.Fatal("expired interactive session regained permission")
	}
	if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET role='readonly' WHERE id=$1`, uid); e != nil {
		t.Fatal(e)
	}
	check(false)
	if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET role='admin',state='pending' WHERE id=$1`, uid); e != nil {
		t.Fatal(e)
	}
	check(false)
	if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET state='active' WHERE id=$1`, uid); e != nil {
		t.Fatal(e)
	}
	c.SiteIDs = []string{uuid.NewString()}
	check(false)
	c.SiteIDs = nil
	c.System = true
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error {
		return security.DeliveryWithin(sc, c, app.Event{Kind: "target_health", ResourceID: site.ID})
	}); e == nil {
		t.Fatal("empty system scope became all sites")
	}
}
