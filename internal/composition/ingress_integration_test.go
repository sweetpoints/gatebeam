//go:build integration

package composition

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	ingressapp "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposedIngressAuthenticationAndCatalog(t *testing.T) {
	p := testkit.Postgres(t)
	key := filepath.Join(t.TempDir(), "identity")
	if e := secrets.EnsureIdentity(key); e != nil {
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
	ids := credential.New()
	uid, _ := ids.NewID()
	sid, _ := ids.NewID()
	raw, _ := ids.Random()
	csrf, _ := ids.Random()
	_, e = p.Exec(context.Background(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','admin')`, uid)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(context.Background(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,now()+interval '1 hour')`, sid, uid, ids.Digest(raw), ids.Digest(csrf))
	if e != nil {
		t.Fatal(e)
	}
	request := func(method, path, body, origin, proof, bearer, key string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if proof != "" {
			r.Header.Set("X-CSRF-Token", proof)
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			r.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: raw})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/ingress-capabilities", "", "", "", "", "")
	var capabilities ingressapp.CreationCapabilities
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &capabilities) != nil || !capabilities.CreateTarget || !capabilities.CreateUngroupedSite || !capabilities.ManageGroups {
		t.Fatal("current admin capabilities", w.Code, w.Body.String())
	}
	for _, query := range []string{"?group_ids=invalid", "?group_ids=a&group_ids=b", "?extra=unknown"} {
		if w := request("GET", "/ingress-capabilities"+query, "", "", "", "", ""); w.Code != 400 {
			t.Fatal("unbounded or invalid capability query accepted", w.Code)
		}
	}
	body := `{"name":"rest","config":{"domains":["rest.example.test"]}}`
	if w := request("POST", "/sites", body, "http://localhost", "", "", ""); w.Code != 401 {
		t.Fatalf("CSRF status %d", w.Code)
	}
	if w := request("POST", "/sites", body, "http://evil.test", csrf, "", ""); w.Code != 403 {
		t.Fatal("origin", w.Code)
	}
	if w := request("POST", "/sites", `{"name":"rest","actor":{"user_id":"forged"}}`, "http://localhost", csrf, "", ""); w.Code != 400 {
		t.Fatal("identity body accepted", w.Code)
	}
	w = request("POST", "/sites", body, "http://localhost", csrf, "", "rest-idem")
	if w.Code != 201 {
		t.Fatal("create", w.Code, w.Body.String())
	}
	var revision ingressapp.Revision
	if json.Unmarshal(w.Body.Bytes(), &revision) != nil || revision.Number != 1 || revision.ResourceID == "" {
		t.Fatal("metadata response", w.Body.String())
	}
	again := request("POST", "/sites", body, "http://localhost", csrf, "", "rest-idem")
	if again.Code != 201 || again.Body.String() != w.Body.String() {
		t.Fatal("HTTP replay", again.Code)
	}
	if w = request("GET", "/sites/"+revision.ResourceID, "", "", "", "", ""); w.Code != 200 {
		t.Fatal("runtime catalog remains unavailable", w.Code)
	}

	var state struct {
		Draft struct {
			Enabled *bool `json:"enabled"`
		} `json:"draft"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &state); e != nil || state.Draft.Enabled == nil || !*state.Draft.Enabled {
		t.Fatal("create must default enabled", e, w.Body.String())
	}
	for _, value := range []string{"", `,"enabled":null`} {
		body := `{"expected_revision":1,"config":{"domains":["rest.example.test"]` + value + `}}`
		if w := request("PUT", "/sites/"+revision.ResourceID+"/draft", body, "http://localhost", csrf, "", ""); w.Code != 400 {
			t.Fatal("full draft enabled missing/null accepted", w.Code)
		}
	}

	if w := request("PUT", "/sites/"+revision.ResourceID+"/groups", `{"expected_revision":1}`, "http://localhost", csrf, "", ""); w.Code != 400 {
		t.Fatal("missing group membership replaced relations", w.Code)
	}
	if w = request("GET", "/sites?order=arbitrary", "", "", "", "", ""); w.Code != 400 {
		t.Fatal("unknown query accepted", w.Code)
	}

	for _, address := range []string{"fd00::1", "::1", "fe80::1", "ff02::1", "::", "2001:db8::1"} {
		body := `{"config":{"name":"IPv6","protocol":"http","members":[{"address":"` + address + `","port":8080,"weight":1}],"http_host":"business.example.test","allowed_networks":["fd00::/64"]}}`
		w := request("POST", "/targets", body, "http://localhost", csrf, "", "")
		want := 400
		if address == "fd00::1" {
			want = 201
		}
		if w.Code != want {
			t.Fatalf("IPv6 %s status %d want %d", address, w.Code, want)
		}
	}
	tid, _ := ids.NewID()
	token, _ := ids.Random()
	_, e = p.Exec(context.Background(), `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$3,1,ARRAY['view'],ARRAY[$4],now()+interval '1 hour')`, tid, uid, ids.Digest(token), revision.ResourceID)
	if e != nil {
		t.Fatal(e)
	}
	if w = request("GET", "/sites/"+revision.ResourceID, "", "", "", token, ""); w.Code != 200 {
		t.Fatal("scoped token read denied", w.Code)
	}
	if w = request("PUT", "/sites/"+revision.ResourceID+"/draft", `{"expected_revision":1,"config":{"domains":["rest.example.test"],"enabled":true}}`, "", "", token, ""); w.Code != 403 {
		t.Fatal("view token acquired edit", w.Code)
	}
	if w = request("GET", "/sites/00000000-0000-4000-8000-000000000001", "", "", "", token, ""); w.Code != 403 {
		t.Fatal("unknown UUID accepted", w.Code)
	}
	_, e = p.Exec(context.Background(), `UPDATE identity_tokens SET revoked=true WHERE id=$1`, tid)
	if e != nil {
		t.Fatal(e)
	}
	if w = request("GET", "/sites/"+revision.ResourceID, "", "", "", token, ""); w.Code != 401 {
		t.Fatal("revoked token authenticated", w.Code)
	}
}
