//go:build integration

package access_test

import (
	"context"
	app "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
	"time"
)

type catalog struct{}

func (catalog) SiteGroupsWithin(_ transaction.Scope, id string) ([]string, error) {
	if id == siteA || id == siteB {
		return []string{"00000000-0000-4000-8000-00000000000c"}, nil
	}
	return nil, access.ErrDenied
}

const siteA = "00000000-0000-4000-8000-00000000000a"
const siteB = "00000000-0000-4000-8000-00000000000b"

func TestScopeCannotExpandThroughToken(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	now := time.Now()
	c := credential.New()
	uid, _ := c.NewID()
	sid, _ := c.NewID()
	tid, _ := c.NewID()
	_, e := p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','publisher')`, uid)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($2,$1,$2,$2,1,now()+interval '1 hour')`, uid, sid)
	if e != nil {
		t.Fatal(e)
	}
	s := access.New(postgres.NewRunner(p), repo.New(), audit.New(), c, catalog{}, func() time.Time { return now })
	actor := app.Actor{UserID: uid, AuthVersion: 1, CredentialKind: app.SessionCredential, CredentialID: sid}
	if e = s.Require(ctx, actor, app.Publish, []string{siteA}); e == nil {
		t.Fatal("ungranted account allowed")
	}
	_, e = p.Exec(ctx, `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site',$2)`, uid, siteA)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, actor, app.Publish, []string{siteA}); e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['view'],ARRAY[$3],now()+interval '1 hour')`, tid, uid, siteA)
	if e != nil {
		t.Fatal(e)
	}
	token := app.Actor{UserID: uid, AuthVersion: 1, CredentialKind: app.TokenCredential, CredentialID: tid}
	for _, check := range []struct {
		a   app.Action
		ids []string
	}{{app.Publish, []string{siteA}}, {app.View, []string{siteB}}, {app.View, []string{"00000000-0000-4000-8000-00000000000f"}}} {
		if e = s.Require(ctx, token, check.a, check.ids); e == nil {
			t.Fatal("token scope expanded")
		}
	}
	if e = s.Require(ctx, token, app.View, []string{siteA}); e != nil {
		t.Fatal(e)
	}
	// Current account grants narrow both credentials; group membership belongs to the catalog.
	if e = access.New(postgres.NewRunner(p), repo.New(), audit.New(), c, nil, time.Now).Require(ctx, actor, app.View, []string{siteA}); e == nil {
		t.Fatal("unavailable runtime catalog allowed a site")
	}
	_, e = p.Exec(ctx, `DELETE FROM identity_grants WHERE account_id=$1`, uid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, token, app.View, []string{siteA}); e == nil {
		t.Fatal("revoked account grant survived in token")
	}
	_, e = p.Exec(ctx, `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'group','00000000-0000-4000-8000-00000000000c')`, uid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, actor, app.View, []string{siteB}); e != nil {
		t.Fatal("group grant denied", e)
	}
	if e = s.Require(ctx, token, app.View, []string{siteB}); e == nil {
		t.Fatal("group grant expanded narrow token")
	}
	_, e = p.Exec(ctx, `UPDATE identity_tokens SET expires=now()-interval '1 second' WHERE id=$1`, tid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, token, app.View, []string{siteA}); e == nil {
		t.Fatal("expired token accepted")
	}
	_, e = p.Exec(ctx, `UPDATE identity_tokens SET expires=now()+interval '1 hour' WHERE id=$1`, tid)
	if e != nil {
		t.Fatal(e)
	}
	// Publication tokens are valid when both current publisher authority and token scope allow.
	publishID, _ := c.NewID()
	_, e = p.Exec(ctx, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['publish'],ARRAY[$3],now()+interval '1 hour')`, publishID, uid, siteA)
	if e != nil {
		t.Fatal(e)
	}
	publisherToken := token
	publisherToken.CredentialID = publishID
	if e = s.Require(ctx, publisherToken, app.Publish, []string{siteA}); e != nil {
		t.Fatal("valid scoped publish denied", e)
	}

	_, e = p.Exec(ctx, `UPDATE identity_tokens SET revoked=true WHERE id=$1`, tid)
	if e != nil {
		t.Fatal(e)
	}
	if e = postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error { return s.RequireWithin(sc, token, app.View, []string{siteA}) }); e == nil {
		t.Fatal("revoked token accepted in transaction")
	}
	_, e = p.Exec(ctx, `UPDATE identity_accounts SET role='readonly' WHERE id=$1`, uid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, actor, app.Publish, []string{siteA}); e == nil {
		t.Fatal("downgraded role accepted")
	}
	_, e = p.Exec(ctx, `UPDATE identity_accounts SET state='disabled' WHERE id=$1`, uid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, actor, app.View, []string{siteA}); e == nil {
		t.Fatal("disabled account accepted")
	}
}
func TestAuthorizationWatermarkOrdersRevocation(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	c := credential.New()
	uid, _ := c.NewID()
	tid, _ := c.NewID()
	_, e := p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','admin')`, uid)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['view'],ARRAY[$3],now()+interval '1 hour')`, tid, uid, siteA)
	if e != nil {
		t.Fatal(e)
	}
	r := repo.New()
	tx := postgres.NewRunner(p)
	s := access.New(tx, r, audit.New(), c, catalog{}, time.Now)
	actor := app.Actor{UserID: uid, AuthVersion: 1, CredentialKind: app.TokenCredential, CredentialID: tid}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- tx.Within(ctx, func(sc transaction.Scope) error {
			if e := s.RequireWithin(sc, actor, app.View, []string{siteA}); e != nil {
				return e
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(3 * time.Second):
		t.Fatal("read lock deadline")
	}
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	e = tx.Within(bounded, func(sc transaction.Scope) error {
		if e := r.Lock(sc); e != nil {
			return e
		}
		return r.RevokeToken(sc, tid)
	})
	close(release)
	if e == nil {
		t.Fatal("revocation crossed held publication authorization lock")
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = tx.Within(ctx, func(sc transaction.Scope) error {
		if e := r.Lock(sc); e != nil {
			return e
		}
		return r.RevokeToken(sc, tid)
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.Require(ctx, actor, app.View, []string{siteA}); e == nil {
		t.Fatal("post-revocation request accepted")
	}
}
