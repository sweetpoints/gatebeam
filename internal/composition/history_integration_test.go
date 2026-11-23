//go:build integration

package composition

import (
	"errors"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
	"time"
)

func TestHistoryFetchRechecksCurrentTokenAndSiteOnEveryPage(t *testing.T) {
	p := testkit.Postgres(t)
	ids := credential.New()
	uid, _ := ids.NewID()
	tid, _ := ids.NewID()
	site, _ := ids.NewID()
	ctx := t.Context()
	fixture, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer fixture.Rollback(ctx)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','readonly')`, []any{uid}},
		{`INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$1,1,ARRAY['view'],ARRAY[$3],now()+interval '1 hour')`, []any{tid, uid, site}},
		{`INSERT INTO ingress_sites(id,name,draft_revision) VALUES($1,'history',1)`, []any{site}},
		{`INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site',$2)`, []any{uid, site}},
	} {
		if _, e := fixture.Exec(ctx, q.sql, q.args...); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = fixture.Exec(ctx, `INSERT INTO ingress_site_revisions(site_id,revision,config) VALUES($1,1,'{}')`, site); e != nil {
		t.Fatal(e)
	}
	if e = fixture.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	service := NewHistory(p)
	actor := query.ActorRef{UserID: uid, CredentialID: tid, CredentialKind: "token", AuthVersion: 1}
	now := time.Now()
	job, e := service.Submit(ctx, actor, query.Filter{SiteIDs: []string{site}, From: now, To: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	r := repo.New()
	tx := postgres.NewRunner(p)
	if e = tx.Within(ctx, func(sc transaction.Scope) error {
		in, found, e := r.ClaimWithin(sc)
		if e != nil {
			return e
		}
		if !found {
			return errors.New("job missing")
		}
		return r.CompleteWithin(sc, in, make([]domain.QueryRow, 101), "")
	}); e != nil {
		t.Fatal(e)
	}
	first, e := service.Fetch(ctx, actor, job.ID, "")
	if e != nil || len(first.Rows) != 100 || first.Cursor != "100" {
		t.Fatal("first page", e, first.Cursor)
	}
	if _, e = p.Exec(ctx, `UPDATE identity_tokens SET revoked=true WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	if _, e = service.Fetch(ctx, actor, job.ID, first.Cursor); !errors.Is(e, domain.ErrDenied) {
		t.Fatal("revoked token fetched cached page", e)
	}
	if _, e = p.Exec(ctx, `UPDATE identity_tokens SET revoked=false WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `DELETE FROM identity_grants WHERE account_id=$1`, uid); e != nil {
		t.Fatal(e)
	}
	if _, e = service.Fetch(ctx, actor, job.ID, first.Cursor); !errors.Is(e, domain.ErrDenied) {
		t.Fatal("removed site grant fetched cached page", e)
	}
}
