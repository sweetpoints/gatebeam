//go:build integration

package composition

import (
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditHTTPRequiresCurrentAuthorityAndCredentialAndOmitsPayload(t *testing.T) {
	p := testkit.Postgres(t)
	path := filepath.Join(t.TempDir(), "api.agekey")
	if e := secrets.EnsureIdentity(path); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(path)
	if e != nil {
		t.Fatal(e)
	}
	h, e := newAPIHandler(p, se, authHTTP.Config{Origin: "http://localhost"})
	if e != nil {
		t.Fatal(e)
	}
	ids := credential.New()
	uid, _ := ids.NewID()
	sid, _ := ids.NewID()
	raw, _ := ids.Random()
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role)VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','admin')`, uid); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires)VALUES($1,$2,$3,'unused',1,clock_timestamp()+interval '1 hour')`, sid, uid, ids.Digest(raw)); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO audit(id,actor_id,action,payload)VALUES('owned-audit',$1,'identity.token.revoked','{"private_key":"AUDIT_SECRET","arbitrary":{"token":"AUDIT_SECRET"}}')`, uid); e != nil {
		t.Fatal(e)
	}
	get := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/audit?limit=25&offset=0", nil)
		r.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: raw})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := get()
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &body); e != nil || len(body.Items) != 1 {
		t.Fatal("audit metadata missing")
	}
	if len(body.Items[0]) != 4 || strings.Contains(w.Body.String(), "AUDIT_SECRET") || strings.Contains(w.Body.String(), "payload") {
		t.Fatal("audit payload leaked")
	}
	if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET role='readonly' WHERE id=$1`, uid); e != nil {
		t.Fatal(e)
	}
	if w = get(); w.Code != 403 {
		t.Fatal("stale admin authority read audit", w.Code)
	}
	if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET role='admin' WHERE id=$1;`, uid); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `UPDATE identity_sessions SET revoked=true WHERE id=$1`, sid); e != nil {
		t.Fatal(e)
	}
	if w = get(); w.Code != 401 {
		t.Fatal("revoked credential read audit", w.Code)
	}
}
