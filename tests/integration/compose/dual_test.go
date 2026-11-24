//go:build integration

package compose_test

import (
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	"gatebeam/internal/platform/secrets"
	labfixture "gatebeam/tests/fixtures/multinode"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTwoProjectsShareExternalPostgresAndPeerTLS(t *testing.T) {
	lab := labfixture.Start(t)
	a, b := lab.Nodes[0], lab.Nodes[1]
	ctx := t.Context()
	ids := credential.New()
	uid, sid := uuid.NewString(), uuid.NewString()
	cookie, e := ids.Random()
	if e != nil {
		t.Fatal(e)
	}
	csrf, e := ids.Random()
	if e != nil {
		t.Fatal(e)
	}
	var publics []string
	for _, n := range lab.Nodes {
		key, e := secrets.New(filepath.Join(n.Secrets["management"], "identity.agekey"))
		if e != nil {
			t.Fatal(e)
		}
		publics = append(publics, key.Recipient())
	}
	key, e := secrets.NewRoleStore(filepath.Join(a.Secrets["management"], "identity.agekey"), publics)
	if e != nil {
		t.Fatal(e)
	}
	otp, e := totp.Generate(totp.GenerateOpts{Issuer: "owned-dual", AccountName: "replica"})
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := key.Seal("identity/totp/"+uid, []byte(otp.Secret()))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lab.Pool.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = lab.Pool.Exec(ctx, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,clock_timestamp()+interval '1 hour')`, sid, uid, ids.Digest(cookie), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	for _, n := range lab.Nodes {
		code, _ := n.Request(t, "GET", "/auth/session", nil, cookie, csrf)
		if code != 200 {
			t.Fatal("same session did not work across projects", code)
		}
	}
	code, raw := a.Request(t, "POST", "/sites", []byte(`{"name":"owned local query","group_ids":[],"config":{"enabled":true,"domains":["owned-local.dual.test"],"maintenance":{"enabled":true,"status":503,"message":"owned"}}}`), cookie, csrf)
	if code != 201 {
		t.Fatal("site creation failed", code, string(raw))
	}
	var site struct {
		ID string `json:"resource_id"`
	}
	if json.Unmarshal(raw, &site) != nil || site.ID == "" {
		t.Fatal("missing owned site")
	}
	body, _ := json.Marshal(map[string]any{"source": "local", "SiteIDs": []string{site.ID}, "From": time.Now().Add(-time.Hour), "To": time.Now().Add(time.Minute)})
	code, raw = a.Request(t, "POST", "/log-queries", body, cookie, csrf)
	if code != 202 {
		t.Fatal("dual local query could not freeze both targets", code, string(raw))
	}
	var job struct{ ID string }
	if json.Unmarshal(raw, &job) != nil || job.ID == "" {
		t.Fatal("missing query ID")
	}
	deadline := time.Now().Add(8 * time.Second)
	complete := false
	for time.Now().Before(deadline) {
		code, raw = b.Request(t, "GET", "/log-queries/"+job.ID, nil, cookie, csrf)
		var page struct {
			Job struct{ State, Coverage string }
		}
		if code == 200 && json.Unmarshal(raw, &page) == nil && page.Job.State == "succeeded" {
			if page.Job.Coverage != "local_complete" {
				t.Fatal("healthy pair coverage incorrect", page.Job.Coverage)
			}
			complete = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !complete {
		t.Fatal("scoped workers did not finish local query", string(raw))
	}
	a.Compose(t, "stop", "--timeout", "2", "management")
	code, _ = a.Request(t, "GET", "/auth/session", nil, cookie, csrf)
	if code != 200 {
		t.Fatal("A entry did not use B API over mTLS", code)
	}
	if _, e = lab.Pool.Exec(ctx, `UPDATE identity_sessions SET revoked=true WHERE id=$1`, sid); e != nil {
		t.Fatal(e)
	}
	for _, n := range lab.Nodes {
		code, _ = n.Request(t, "GET", "/auth/session", nil, cookie, csrf)
		if code != 401 {
			t.Fatal("peer cached a revoked session", code)
		}
	}
	r, e := b.CAClient.Get("https://ca.dual.test:8444/acme/server/directory")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("independent CA lost its stable issuer after A stopped", r.StatusCode)
	}
	for _, n := range lab.Nodes {
		id := n.Compose(t, "ps", "-q", "log-query")
		labfixture.Docker(t, "exec", "-e", "GATEBEAM_CAPABILITY_PROBE=1", id, "/capabilities", "/run/gatebeam/database", "/run/gatebeam/issuer.age", "/run/gatebeam/identity.agekey")
		if !strings.Contains(n.Info.Roles["log-query"].Image, "@sha256:") {
			t.Fatal("mutable query image")
		}
	}
	t.Log("two isolated four-role Compose projects, independent role identities, external PostgreSQL, peer API TLS, shared/revoked session, scoped local queries and surviving CA verified")
}
