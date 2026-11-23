//go:build integration

package auth_test

import (
	"context"
	"fmt"
	app "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMissingAuthorityGrantsCannotClearScopeOrConsumeTOTP(t *testing.T) {
	ctx := context.Background()
	s, now, p := fixture(t)
	s.SetAccess(access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), knownSites{}, func() time.Time { return *now }))
	invite, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, invite.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, e := s.BeginLogin(ctx, "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	sess, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,'site','00000000-0000-4000-8000-000000000001')`, sess.Actor.UserID)
	if e != nil {
		t.Fatal(e)
	}
	var before int64
	if e = p.QueryRow(ctx, "SELECT last_step FROM identity_accounts WHERE id=$1", sess.Actor.UserID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	proof := code(t, seed, *now)
	handler, e := authHTTP.New(s, p.Ping, authHTTP.Config{Origin: "https://admin.example", Production: true})
	if e != nil {
		t.Fatal(e)
	}
	checkUnchanged := func() {
		t.Helper()
		var role string
		var step int64
		var grants int
		if e = p.QueryRow(ctx, "SELECT role,last_step,(SELECT count(*) FROM identity_grants WHERE account_id=$1) FROM identity_accounts WHERE id=$1", sess.Actor.UserID).Scan(&role, &step, &grants); e != nil || role != "admin" || step != before || grants != 1 {
			t.Fatalf("rejected update mutated state role=%s step=%d grants=%d err=%v", role, step, grants, e)
		}
	}
	for _, field := range []string{"", `,"grants":null`} {
		body := fmt.Sprintf(`{"role":"readonly","totp_code":%q%s}`, proof, field)
		req := httptest.NewRequest("PUT", "/accounts/"+sess.Actor.UserID+"/authority", strings.NewReader(body))
		req.Header.Set("Origin", "https://admin.example")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sess.CSRFToken)
		req.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: sess.Token})
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != 400 {
			t.Errorf("missing/null grants status=%d body=%s", out.Code, out.Body.String())
		}
		checkUnchanged()
	}
	if e = s.SetAuthority(ctx, sess.Actor, proof, sess.Actor.UserID, app.Readonly, nil); e == nil {
		t.Error("application accepted nil grants")
	}
	checkUnchanged()
	body := fmt.Sprintf(`{"role":"readonly","totp_code":%q,"grants":[]}`, proof)
	req := httptest.NewRequest("PUT", "/accounts/"+sess.Actor.UserID+"/authority", strings.NewReader(body))
	req.Header.Set("Origin", "https://admin.example")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: sess.Token})
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 204 {
		t.Fatal(out.Code, out.Body.String())
	}
	var grants int
	var role string
	var step int64
	if e = p.QueryRow(ctx, "SELECT role,last_step,(SELECT count(*) FROM identity_grants WHERE account_id=$1) FROM identity_accounts WHERE id=$1", sess.Actor.UserID).Scan(&role, &step, &grants); e != nil || role != "readonly" || grants != 0 || step <= before {
		t.Fatal("explicit empty grants did not commit", role, step, grants, e)
	}
}
func TestDocumentedBodylessLogout(t *testing.T) {
	ctx := context.Background()
	s, now, p := fixture(t)
	invite, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, invite.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, e := s.BeginLogin(ctx, "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	sess, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	h, e := authHTTP.New(s, p.Ping, authHTTP.Config{Origin: "https://admin.example", Production: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		origin, csrf string
		want         int
	}{{"https://wrong.example", sess.CSRFToken, 403}, {"https://admin.example", "wrong", 401}, {"https://admin.example", sess.CSRFToken, 204}} {
		req := httptest.NewRequest("POST", "/auth/logout", nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("X-CSRF-Token", tc.csrf)
		req.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: sess.Token})
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != tc.want {
			t.Errorf("documented bodyless logout: got %d want %d body=%s", out.Code, tc.want, out.Body.String())
		}
	}
	if _, e = s.Authenticate(ctx, sess.Token); e == nil {
		t.Fatal("logout did not revoke session")
	}
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"name":"admin","password":"a long enough password"}`))
	req.Header.Set("Origin", "https://admin.example")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 415 {
		t.Fatal("body-bearing login bypassed JSON media requirement", out.Code)
	}
}
