//go:build integration

package composition

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"github.com/pquerna/otp/totp"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateHTTPCurrentScopeMetadataAndSensitiveWrites(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	keys := []*secrets.Store{}
	for _, name := range []string{"api", "leaf", "provider"} {
		path := filepath.Join(t.TempDir(), name)
		if e := secrets.EnsureIdentity(path); e != nil {
			t.Fatal(e)
		}
		s, e := secrets.New(path)
		if e != nil {
			t.Fatal(e)
		}
		keys = append(keys, s)
	}
	for _, cfg := range []bootstrap.Config{{CertificateRecipient: keys[0].Recipient()}, {CertificateProviderRecipient: keys[0].Recipient()}, {CARecipient: keys[1].Recipient(), CertificateRecipient: keys[1].Recipient()}} {
		if _, err := newAPIHandlerWithPKI(p, keys[0], nil, cfg, authHTTP.Config{Origin: "http://localhost"}); err == nil {
			t.Fatal("API/CA recipient reuse accepted")
		}
	}
	handler, e := newAPIHandlerWithPKI(p, keys[0], nil, bootstrap.Config{CertificateRecipient: keys[1].Recipient(), CertificateProviderRecipient: keys[2].Recipient(), CAIdentityFile: "/unmounted-ca-identity", CASignerFile: "/unmounted-ca-signer", CertificateIdentityFile: "/unmounted-leaf-identity", CertificateProviderIdentityFile: "/unmounted-provider-identity"}, authHTTP.Config{Origin: "http://localhost"})
	if e != nil {
		t.Fatal(e)
	}
	ids := credential.New()
	uid, _ := ids.NewID()
	sid, _ := ids.NewID()
	raw, _ := ids.Random()
	csrf, _ := ids.Random()
	seedKey, _ := totp.Generate(totp.GenerateOpts{Issuer: "owned", AccountName: "admin"})
	seed := seedKey.Secret()
	cipher, _ := keys[0].Seal("identity/totp/"+uid, []byte(seed))
	if _, e = p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,now()+interval '1 hour')`, sid, uid, ids.Digest(raw), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	request := func(method, path string, body any, token string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://localhost")
		r.Header.Set("X-CSRF-Token", csrf)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		} else {
			r.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: raw})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	proof := func() string {
		if _, e = p.Exec(ctx, "UPDATE identity_accounts SET last_step=-1 WHERE id=$1", uid); e != nil {
			t.Fatal(e)
		}
		v, e := totp.GenerateCode(seed, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	create := func(kind string, config any, secret string) map[string]any {
		w := request("POST", "/certificates/"+kind, map[string]any{"config": config, "secret": secret, "totp_code": proof()}, "")
		if w.Code != 201 {
			t.Fatalf("%s create: %d %s", kind, w.Code, w.Body.String())
		}
		out := map[string]any{}
		if json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("decode")
		}
		return out
	}
	for _, path := range []string{"/pki/sign", "/pki/issue", "/certificates/spec/00000000-0000-4000-8000-000000000001/sign"} {
		if w := request("POST", path, map[string]string{"csr": "not-a-management-contract"}, ""); w.Code != 404 {
			t.Fatal("private signing route exposed", path, w.Code)
		}
	}
	if w := request("POST", "/certificates/spec", map[string]any{"csr": "untrusted-csr", "totp_code": proof()}, ""); w.Code != 400 {
		t.Fatal("unknown CSR accepted in management body", w.Code)
	}
	credentialConfig := map[string]any{"zone_id": strings.Repeat("a", 32), "zone_name": "owned.test"}
	cred := create("credential", credentialConfig, "owned-CF-token")
	unreferenced := create("credential", map[string]any{"zone_id": strings.Repeat("b", 32), "zone_name": "hidden.test"}, "other-secret")
	account := create("account", map[string]any{"provider": "letsencrypt", "email": "owned@example.test"}, "")
	specConfig := map[string]any{"names": []string{"entry.owned.test"}, "purpose": "serverAuth", "method": "acme", "provider_id": account["id"], "challenge": "dns-01", "credential_ids": []any{cred["id"]}}
	spec := create("spec", specConfig, "")
	sites := []string{}
	for _, name := range []string{"alpha.owned.test", "beta.owned.test"} {
		w := request("POST", "/sites", map[string]any{"name": name, "group_ids": []string{}, "config": map[string]any{"enabled": true, "domains": []string{name}, "entry_certificate": map[string]any{"id": spec["id"], "revision": 1, "status": "unavailable"}, "maintenance": map[string]any{"enabled": true, "status": 503, "message": "owned"}}}, "")
		if w.Code != 201 {
			t.Fatal("site create", w.Code, w.Body.String())
		}
		var s struct {
			ID string `json:"resource_id"`
		}
		if json.Unmarshal(w.Body.Bytes(), &s) != nil || s.ID == "" {
			t.Fatal("site ID")
		}
		sites = append(sites, s.ID)
	}
	// Reads never consume TOTP and never select or serialize secret material.
	for _, kind := range []string{"account", "credential", "spec"} {
		w := request("GET", "/certificates/"+kind, nil, "")
		if w.Code != 200 {
			t.Fatal("admin read", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "owned-CF-token") || strings.Contains(w.Body.String(), "private_material_ref") {
			t.Fatal("metadata boundary")
		}
	}
	for _, endpoint := range []struct{ method, path string }{
		{"GET", "/pki/management"},
		{"POST", "/pki/grants"},
		{"POST", "/pki/grants/fixture/eab"},
		{"POST", "/pki/principals/fixture/disable"},
		{"POST", "/pki/issuers/fixture/certificates/fixture/revoke"},
	} {
		w := request(endpoint.method, endpoint.path, nil, "")
		if w.Code != 404 {
			t.Fatalf("removed CA endpoint %s %s returned %d", endpoint.method, endpoint.path, w.Code)
		}
	}
	// A site-limited admin-owned token cannot gain global PKI/unreferenced access.
	tokenID, _ := ids.NewID()
	token, _ := ids.Random()
	if _, e = p.Exec(ctx, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$3,1,ARRAY['view'],$4,now()+interval '1 hour')`, tokenID, uid, ids.Digest(token), []string{sites[0]}); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/certificates/spec/" + spec["id"].(string), "/certificates/credential/" + cred["id"].(string), "/certificates/credential/" + unreferenced["id"].(string)} {
		w := request("GET", path, nil, token)
		if w.Code != 403 {
			t.Fatal("site token read escaped scope", path, w.Code, w.Body.String())
		}
	}
	w := request("GET", "/certificates/credential", nil, token)
	if w.Code != 200 || strings.Contains(w.Body.String(), cred["id"].(string)) || strings.Contains(w.Body.String(), unreferenced["id"].(string)) {
		t.Fatal("list leaked inaccessible resource", w.Code, w.Body.String())
	}
	// Editor sees only resources whose complete current reference set is granted.
	if _, e = p.Exec(ctx, "UPDATE identity_accounts SET role='editor' WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site',$2)", uid, sites[0]); e != nil {
		t.Fatal(e)
	}
	if w = request("GET", "/certificates/spec/"+spec["id"].(string), nil, ""); w.Code != 403 {
		t.Fatal("shared resource ignored second draft", w.Code)
	}
	if _, e = p.Exec(ctx, "INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site',$2)", uid, sites[1]); e != nil {
		t.Fatal(e)
	}
	if w = request("GET", "/certificates/spec/"+spec["id"].(string), nil, ""); w.Code != 200 {
		t.Fatal("fully scoped read", w.Code, w.Body.String())
	}
	if w = request("POST", "/certificates/spec/"+spec["id"].(string)+"/enabled", map[string]any{"expected_revision": 1, "enabled": false, "totp_code": proof()}, ""); w.Code != 403 {
		t.Fatal("read scope became management authority", w.Code)
	}
	if _, e = p.Exec(ctx, "UPDATE identity_accounts SET role='admin' WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	// Invalid MFA and stale revisions fail without false success or a version change.
	if w = request("POST", "/certificates/spec/"+spec["id"].(string)+"/enabled", map[string]any{"expected_revision": 1, "enabled": false, "totp_code": "invalid"}, ""); w.Code != 403 {
		t.Fatal("missing MFA status", w.Code)
	}
	if w = request("PUT", "/certificates/spec/"+spec["id"].(string), map[string]any{"expected_revision": 99, "config": specConfig, "totp_code": proof()}, ""); w.Code != 409 {
		t.Fatal("stale revision status", w.Code, w.Body.String())
	}
	if w = request("POST", "/certificates/spec/"+spec["id"].(string)+"/enabled", map[string]any{"expected_revision": 1, "enabled": false, "totp_code": proof()}, ""); w.Code != 204 {
		t.Fatal("disable resource", w.Code, w.Body.String())
	}
	if _, e = p.Exec(ctx, "UPDATE identity_sessions SET revoked=true WHERE id=$1", sid); e != nil {
		t.Fatal(e)
	}
	if w = request("GET", "/certificates/spec", nil, ""); w.Code == 200 {
		t.Fatal("revoked current session read accepted")
	}
}
