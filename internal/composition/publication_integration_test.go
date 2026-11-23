//go:build integration

package composition

import (
	"context"
	"encoding/json"
	"fmt"
	"gatebeam/internal/integration/publication"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	ingress "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposedPublicationAuthenticationVersionDiffAndQueue(t *testing.T) {
	p := testkit.Postgres(t)
	key := filepath.Join(t.TempDir(), "identity")
	if e := secrets.EnsureIdentity(key); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(key)
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
	csrf, _ := ids.Random()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := p.Exec(context.Background(), sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,'','0001-01-01','0001-01-01','admin')`, uid)
	exec(`INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,now()+interval '1 hour')`, sid, uid, ids.Digest(raw), ids.Digest(csrf))
	request := func(method, path, body, origin, proof, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if proof != "" {
			r.Header.Set("X-CSRF-Token", proof)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			r.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: raw})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/sites", `{"name":"release","config":{"domains":["release.example.test"]}}`, "http://localhost", csrf, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var revision ingress.Revision
	if e = json.Unmarshal(w.Body.Bytes(), &revision); e != nil {
		t.Fatal(e)
	}
	body := fmt.Sprintf(`{"site_ids":[%q],"expected":{"site:%s":1}}`, revision.ResourceID, revision.ResourceID)
	if w = request("POST", "/releases/prepare", body, "http://localhost", "", ""); w.Code != 401 {
		t.Fatal("CSRF missing accepted", w.Code)
	}
	if w = request("POST", "/releases/prepare", body, "http://evil.test", csrf, ""); w.Code != 403 {
		t.Fatal("foreign origin accepted", w.Code)
	}
	if w = request("POST", "/releases/prepare", strings.TrimSuffix(body, "}")+`,"actor":{"user_id":"forged"}}`, "http://localhost", csrf, ""); w.Code != 400 {
		t.Fatal("actor spoof accepted", w.Code)
	}
	w = request("POST", "/releases/prepare", body, "http://localhost", csrf, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var candidate publication.CandidateView
	if e = json.Unmarshal(w.Body.Bytes(), &candidate); e != nil || candidate.ID == "" {
		t.Fatal(e, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "release.example.test") || strings.Contains(w.Body.String(), "snapshot") {
		t.Fatal("config leaked")
	}
	if w = request("POST", "/releases/"+candidate.ID+"/prepare-historical", body, "http://localhost", csrf, ""); w.Code != 400 {
		t.Fatal("unverified source accepted by historical endpoint", w.Code, w.Body.String())
	}

	for _, path := range []string{"/releases", "/releases/" + candidate.ID, "/releases/" + candidate.ID + "/diff"} {
		if w = request("GET", path, "", "", "", ""); w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	tokenID, _ := ids.NewID()
	token, _ := ids.Random()
	exec(`INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$3,1,ARRAY['view'],ARRAY[$4],now()+interval '1 hour')`, tokenID, uid, ids.Digest(token), revision.ResourceID)

	// Metadata reads require view authority, independent from publish authority.
	exec(`INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site',$2)`, uid, revision.ResourceID)
	for _, role := range []string{"readonly", "editor"} {
		exec(`UPDATE identity_accounts SET role=$2 WHERE id=$1`, uid, role)
		for _, bearer := range []string{"", token} {
			for _, path := range []string{"/releases", "/releases/" + candidate.ID, "/releases/" + candidate.ID + "/diff"} {
				w = request("GET", path, "", "", "", bearer)
				if w.Code != 200 || !strings.Contains(w.Body.String(), candidate.ID) {
					t.Errorf("%s view credential=%t GET %s = %d %s", role, bearer != "", path, w.Code, w.Body.String())
				}
			}
			if w = request("POST", "/releases/prepare", body, "http://localhost", csrf, bearer); w.Code != 403 {
				t.Errorf("%s prepare allowed credential=%t: %d", role, bearer != "", w.Code)
			}
			if w = request("POST", "/releases/"+candidate.ID+"/publish", "", "http://localhost", csrf, bearer); w.Code != 403 {
				t.Errorf("%s publish allowed credential=%t: %d", role, bearer != "", w.Code)
			}
		}
	}
	exec(`UPDATE identity_accounts SET role='admin' WHERE id=$1`, uid)
	if w = request("POST", "/releases/"+candidate.ID+"/publish", "", "", "", token); w.Code != 403 {
		t.Fatal("view token published", w.Code)
	}
	exec(`UPDATE identity_tokens SET actions=ARRAY['publish'] WHERE id=$1`, tokenID)
	for range 2 {
		w = request("POST", "/releases/"+candidate.ID+"/publish", "", "", "", token)
		if w.Code != 202 || !strings.Contains(w.Body.String(), `"effective":false`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var jobs, heads int
	if e = p.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE kind='deployment.apply'`).Scan(&jobs); e != nil || jobs != 1 {
		t.Fatal(jobs, e)
	}
	if e = p.QueryRow(context.Background(), `SELECT count(*) FROM ingress_sites WHERE published_revision IS NOT NULL`).Scan(&heads); e != nil || heads != 0 {
		t.Fatal("queue advanced ingress", heads, e)
	}
	// Owned verified-source fixture for I2 HTTP orchestration only; no runtime apply.
	exec(`UPDATE deployment_releases SET state='succeeded' WHERE id=$1`, candidate.ID)
	w = request("POST", "/releases/"+candidate.ID+"/prepare-historical", body, "http://localhost", csrf, "")
	if w.Code != 201 {
		t.Fatal("historical HTTP prepare", w.Code, w.Body.String())
	}
	var restored publication.CandidateView
	if e = json.Unmarshal(w.Body.Bytes(), &restored); e != nil || restored.ID == candidate.ID || restored.ID == "" {
		t.Fatal("history reused source", e, w.Body.String())
	}

	exec(`UPDATE identity_tokens SET revoked=true WHERE id=$1`, tokenID)
	if w = request("POST", "/releases/"+candidate.ID+"/publish", "", "", "", token); w.Code != 401 {
		t.Fatal("revoked token accepted", w.Code)
	}
}
