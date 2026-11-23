//go:build integration

package composition

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
)

func TestHistoryListContinuesAfterCurrentScopeFiltering(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	ids := credential.New()
	uid, _ := ids.NewID()
	tid, _ := ids.NewID()
	a, _ := ids.NewID()
	b, _ := ids.NewID()
	rawToken, _ := ids.Random()
	tx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role)VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','readonly')`, []any{uid}},
		{`INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires)VALUES($1,$2,$3,1,ARRAY['view'],ARRAY[$4,$5],clock_timestamp()+interval '1 hour')`, []any{tid, uid, ids.Digest(rawToken), a, b}},
	}
	for _, s := range statements {
		if _, e = tx.Exec(ctx, s.sql, s.args...); e != nil {
			t.Fatal(e)
		}
	}
	for _, site := range []string{a, b} {
		for _, s := range []string{`INSERT INTO ingress_sites(id,name,draft_revision)VALUES($1,'history-pagination',1)`, `INSERT INTO ingress_site_revisions(site_id,revision,config)VALUES($1,1,'{}')`} {
			if _, e = tx.Exec(ctx, s, site); e != nil {
				t.Fatal(e)
			}
		}
		if _, e = tx.Exec(ctx, `INSERT INTO identity_grants(account_id,kind,resource_id)VALUES($1,'site',$2)`, uid, site); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	service := NewHistory(p)
	actor := query.ActorRef{UserID: uid, CredentialKind: "token", CredentialID: tid, AuthVersion: 1}
	from := time.Now()
	old, e := service.Submit(ctx, actor, query.Filter{SiteIDs: []string{a}, From: from, To: from.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	hidden := []string{}
	for i := 0; i < 26; i++ {
		job, e := service.Submit(ctx, actor, query.Filter{SiteIDs: []string{b}, From: from, To: from.Add(time.Hour)})
		if e != nil {
			t.Fatal(e)
		}
		hidden = append(hidden, job.ID)
	}
	if _, e = p.Exec(ctx, `DELETE FROM identity_grants WHERE account_id=$1 AND resource_id=$2`, uid, b); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(t.TempDir(), "api.agekey")
	if e = secrets.EnsureIdentity(key); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := newAPIHandler(p, se, authHTTP.Config{Origin: "http://localhost"})
	if e != nil {
		t.Fatal(e)
	}
	type listing struct {
		Items      []query.Job `json:"items"`
		HasMore    bool        `json:"has_more"`
		NextOffset int         `json:"next_offset"`
	}
	get := func(offset int) (listing, int) {
		t.Helper()
		req := httptest.NewRequest("GET", fmt.Sprintf("/log-queries?limit=25&offset=%d", offset), nil)
		req.Header.Set("Authorization", "Bearer "+rawToken)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != 200 {
			return listing{}, res.Code
		}
		var out listing
		if e := json.Unmarshal(res.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		for _, id := range append(hidden, b) {
			if strings.Contains(res.Body.String(), id) {
				t.Fatal("current unauthorized B metadata exposed")
			}
		}
		return out, res.Code
	}
	first, status := get(0)
	if status != 200 {
		t.Fatal("first page", status)
	}
	if len(first.Items) != 0 || !first.HasMore || first.NextOffset != 25 {
		t.Fatalf("filtered raw page hid continuation: visible=%d has_more=%v next_offset=%d", len(first.Items), first.HasMore, first.NextOffset)
	}
	next, status := get(first.NextOffset)
	if status != 200 || len(next.Items) != 1 || next.Items[0].ID != old.ID || next.HasMore {
		t.Fatal("older authorized A job unreachable", status, len(next.Items), next.HasMore)
	}
	if _, e = p.Exec(ctx, `UPDATE identity_tokens SET revoked=true WHERE id=$1`, tid); e != nil {
		t.Fatal(e)
	}
	if _, status = get(25); status != 401 {
		t.Fatal("revoked credential followed continuation", status)
	}
}
