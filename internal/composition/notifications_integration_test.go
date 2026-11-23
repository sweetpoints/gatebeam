//go:build integration

package composition

import (
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	app "gatebeam/internal/modules/notification/application"
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

func TestNotificationHTTPFreshMFAPublicSealAndSafeRead(t *testing.T) {
	p := testkit.Postgres(t)
	newSecret := func() *secrets.Store {
		t.Helper()
		path := filepath.Join(t.TempDir(), "identity")
		if e := secrets.EnsureIdentity(path); e != nil {
			t.Fatal(e)
		}
		s, e := secrets.New(path)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	api, worker := newSecret(), newSecret()
	ids := credential.New()
	uid, _ := ids.NewID()
	sid, _ := ids.NewID()
	cookie, _ := ids.Random()
	csrf, _ := ids.Random()
	seedKey, e := totp.Generate(totp.GenerateOpts{Issuer: "owned", AccountName: "admin"})
	if e != nil {
		t.Fatal(e)
	}
	seed := seedKey.Secret()
	cipher, e := api.Seal("identity/totp/"+uid, []byte(seed))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,now()+interval '1 hour')`, sid, uid, ids.Digest(cookie), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	handler, e := newAPIHandlerWithPKI(p, api, nil, bootstrap.Config{NotificationRecipient: worker.Recipient()}, authHTTP.Config{Origin: "http://localhost"})
	if e != nil {
		t.Fatal(e)
	}
	request := func(method, path string, value any) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(value)
		req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://localhost")
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: cookie})
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	code, e := totp.GenerateCode(seed, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	input := map[string]any{"channel": map[string]any{"kind": "telegram", "enabled": true, "system": true, "recipient": "123"}, "expected_revision": 0, "secret": "123:SECRET", "totp": "bad"}
	if res := request("PUT", "/alert-channels", input); res.Code != 403 {
		t.Fatal("missing fresh MFA", res.Code, res.Body.String())
	}
	input["totp"] = code
	res := request("PUT", "/alert-channels", input)
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "SECRET") {
		t.Fatal("response exposed secret")
	}
	var channel app.Channel
	if json.Unmarshal(res.Body.Bytes(), &channel) != nil || channel.OwnerID != uid {
		t.Fatal("owner not assigned")
	}
	var stored []byte
	if e = p.QueryRow(t.Context(), `SELECT secret FROM notification_channels WHERE id=$1`, channel.ID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if _, e = api.Open("notification/channel/"+channel.ID, stored); e == nil {
		t.Fatal("API identity decrypted worker secret")
	}
	plain, e := worker.Open("notification/channel/"+channel.ID, stored)
	if e != nil || string(plain) != "123:SECRET" {
		t.Fatal("worker cannot decrypt", e)
	}
	clear(plain)
	if res = request("POST", "/alert-channels/"+channel.ID+"/test", map[string]string{"totp": code}); res.Code != 403 {
		t.Fatal("reused TOTP accepted", res.Code)
	}
	var before, after int64
	if e = p.QueryRow(t.Context(), `SELECT last_step FROM identity_accounts WHERE id=$1`, uid).Scan(&before); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/alert-channels", "/alerts"} {
		res = request("GET", path, nil)
		if res.Code != 200 || strings.Contains(res.Body.String(), "SECRET") {
			t.Fatal("safe query", res.Code, res.Body.String())
		}
	}
	if e = p.QueryRow(t.Context(), `SELECT last_step FROM identity_accounts WHERE id=$1`, uid).Scan(&after); e != nil || before != after {
		t.Fatal("read consumed TOTP", e)
	}
	next, e := totp.GenerateCode(seed, time.Unix((before+1)*30, 0))
	if e != nil {
		t.Fatal(e)
	}
	res = request("POST", "/alert-channels/"+channel.ID+"/test", map[string]string{"totp": next})
	if res.Code != 202 {
		t.Fatal("safe async test", res.Code, res.Body.String())
	}
	var jobs, sends int
	if e = p.QueryRow(t.Context(), `SELECT count(*) FROM jobs WHERE kind='notification.delivery'`).Scan(&jobs); e != nil || jobs != 1 {
		t.Fatal(jobs, e)
	}
	if e = p.QueryRow(t.Context(), `SELECT count(*) FROM notification_attempts`).Scan(&sends); e != nil || sends != 0 {
		t.Fatal("API performed external delivery", sends, e)
	}
	if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET role='readonly' WHERE id=$1`, uid); e != nil {
		t.Fatal(e)
	}
	if res = request("GET", "/alert-channels", nil); res.Code != 403 {
		t.Fatal("stale admin permission", res.Code)
	}
}
