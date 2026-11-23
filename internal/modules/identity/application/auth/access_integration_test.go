//go:build integration

package auth_test

import (
	"context"
	app "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type knownSites struct{}

func (knownSites) SiteGroupsWithin(_ transaction.Scope, id string) ([]string, error) {
	if id == "00000000-0000-4000-8000-000000000001" {
		return nil, nil
	}
	return nil, access.ErrDenied
}
func TestAccountManagementAndTokenAudit(t *testing.T) {
	ctx := context.Background()
	s, now, p := fixture(t)
	ac := access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), knownSites{}, func() time.Time { return *now })
	s.SetAccess(ac)
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
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
	*now = now.Add(30 * time.Second)
	otp := code(t, seed, *now)
	v, e := s.CreateAccount(ctx, sess.Actor, otp, "operator", app.Editor)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(ctx, v.InviteID); e == nil {
		t.Fatal("new invitation became session")
	}
	if _, e = s.CreateAccount(ctx, sess.Actor, otp, "replay", app.Editor); e == nil {
		t.Fatal("TOTP replay allowed")
	}
	*now = now.Add(30 * time.Second)
	issued, e := s.IssueToken(ctx, sess.Actor, code(t, seed, *now), []string{"view"}, []string{"00000000-0000-4000-8000-000000000001"}, now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if len(issued.Token) != 43 {
		t.Fatal("token entropy encoding")
	}
	actor, e := s.AuthenticateToken(ctx, issued.Token)
	if e != nil {
		t.Fatal(e)
	}
	if e = ac.Require(ctx, actor, app.Manage, nil); e == nil {
		t.Fatal("token managed accounts")
	}
	if _, e = s.IssueToken(ctx, actor, code(t, seed, *now), []string{"view"}, []string{"00000000-0000-4000-8000-000000000001"}, now.Add(time.Hour)); e == nil {
		t.Fatal("token minted token")
	}
	if e = s.RevokeToken(ctx, actor, code(t, seed, *now), issued.ID); e == nil {
		t.Fatal("token revoked token without session")
	}

	if e = ac.Require(ctx, actor, app.Publish, []string{"00000000-0000-4000-8000-000000000001"}); e == nil {
		t.Fatal("mapped token widened")
	}
	var hash string
	if e = p.QueryRow(ctx, "SELECT digest FROM identity_tokens WHERE id=$1", issued.ID).Scan(&hash); e != nil || hash == issued.Token {
		t.Fatal("raw token stored", e)
	}
	var body string
	if e = p.QueryRow(ctx, "SELECT string_agg(payload::text,'') FROM audit").Scan(&body); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(body, issued.Token) || strings.Contains(body, seed) || strings.Contains(body, otp) {
		t.Fatal("audit leaks secret")
	}
	*now = now.Add(30 * time.Second)
	if e = s.RevokeToken(ctx, sess.Actor, code(t, seed, *now), issued.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.AuthenticateToken(ctx, issued.Token); e == nil {
		t.Fatal("revoked token authenticated")
	}
	*now = now.Add(30 * time.Second)
	if e = s.SetAuthority(ctx, sess.Actor, code(t, seed, *now), sess.Actor.UserID, app.Readonly, []domain.Grant{}); e != nil {
		t.Fatal(e)
	}
	if _, e = ac.Accounts(ctx, sess.Actor, 25, 0); e == nil {
		t.Fatal("downgraded admin enumerated accounts")
	}
}
func TestSensitiveTOTPFailuresCommitAndAuditRollback(t *testing.T) {
	ctx := context.Background()
	s, now, p := fixture(t)
	ac := access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), knownSites{}, func() time.Time { return *now })
	s.SetAccess(ac)
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, _ := s.BeginLogin(ctx, "admin", "a long enough password")
	sess, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	for j := 0; j < 5; j++ {
		if _, e = s.CreateAccount(ctx, sess.Actor, "bad", "operator", app.Editor); e == nil {
			t.Fatal("bad TOTP allowed")
		}
	}
	var locked time.Time
	if e = p.QueryRow(ctx, "SELECT locked_until FROM identity_accounts WHERE id=$1", sess.Actor.UserID).Scan(&locked); e != nil || !locked.After(*now) {
		t.Fatal("failure budget rolled back", e)
	}
}
func TestManagementRESTAndBearerAuthentication(t *testing.T) {
	ctx := context.Background()
	s, now, p := fixture(t)
	s.SetAccess(access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), knownSites{}, func() time.Time { return *now }))
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, _ := s.BeginLogin(ctx, "admin", "a long enough password")
	sess, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	handler, e := authHTTP.New(s, p.Ping, authHTTP.Config{Origin: "https://admin.example", Production: true})
	if e != nil {
		t.Fatal(e)
	}
	req := httptest.NewRequest("GET", "/accounts?limit=25&offset=0", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: sess.Token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items"`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
	*now = now.Add(30 * time.Second)
	raw, e := s.IssueToken(ctx, sess.Actor, code(t, seed, *now), []string{"view"}, []string{"00000000-0000-4000-8000-000000000001"}, now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	req = httptest.NewRequest("GET", "/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+raw.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"credential_kind":"token"`) {
		t.Fatal(rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/accounts", 403}, {"GET", "/tokens", 403}, {"GET", "/audit", 403}, {"POST", "/auth/logout", 401}} {
		req = httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+raw.Token)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"request_id"`) {
			t.Fatal(tc.path, rec.Code, rec.Body.String())
		}
	}

}
func TestSensitiveAuditFailureRollsBackTokenAndProof(t *testing.T) {
	ctx := context.Background()
	writer := &failAudit{}
	s, now, p := fixture(t, writer)
	s.SetAccess(access.New(postgres.NewRunner(p), repo.New(), writer, credential.New(), knownSites{}, func() time.Time { return *now }))
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, _ := s.BeginLogin(ctx, "admin", "a long enough password")
	sess, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	proof := code(t, seed, *now)
	writer.fail = true
	out, e := s.IssueToken(ctx, sess.Actor, proof, []string{"view"}, []string{"00000000-0000-4000-8000-000000000001"}, now.Add(time.Hour))
	if e == nil || out.Token != "" {
		t.Fatal("audit failure leaked bearer")
	}
	var n int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM identity_tokens").Scan(&n); e != nil || n != 0 {
		t.Fatal("token escaped rollback", e)
	}
	writer.fail = false
	if _, e = s.IssueToken(ctx, sess.Actor, proof, []string{"view"}, []string{"00000000-0000-4000-8000-000000000001"}, now.Add(time.Hour)); e != nil {
		t.Fatal("failed transaction consumed TOTP", e)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='identity.token.created' AND actor_id=$1", sess.Actor.UserID).Scan(&n); e != nil || n != 1 {
		t.Fatal("audit actor missing", e)
	}
}
func TestResetDisableAndReenrollment(t *testing.T) {
	ctx := context.Background()
	s, now, p := fixture(t)
	s.SetAccess(access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), knownSites{}, func() time.Time { return *now }))
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(ctx, i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, _ := s.BeginLogin(ctx, "admin", "a long enough password")
	sess, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	invite, e := s.CreateAccount(ctx, sess.Actor, code(t, seed, *now), "operator", app.Editor)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(invite.ProvisioningURI)
	operatorSeed := u.Query().Get("secret")
	if _, e = s.EnrollTOTP(ctx, invite.InviteID, "operator long password", code(t, operatorSeed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	ch, _ = s.BeginLogin(ctx, "operator", "operator long password")
	operator, e := s.FinishLogin(ctx, ch.ChallengeID, code(t, operatorSeed, *now))
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	reset, e := s.ResetAccount(ctx, sess.Actor, code(t, seed, *now), operator.Actor.UserID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(ctx, operator.Token); e == nil {
		t.Fatal("reset session survived")
	}
	if _, e = s.BeginLogin(ctx, "operator", "operator long password"); e == nil {
		t.Fatal("reset bypassed reenrollment")
	}
	u, _ = url.Parse(reset.ProvisioningURI)
	if _, e = s.EnrollTOTP(ctx, reset.InviteID, "replacement strong password", code(t, u.Query().Get("secret"), *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	if e = s.DisableAccount(ctx, sess.Actor, code(t, seed, *now), operator.Actor.UserID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.BeginLogin(ctx, "operator", "replacement strong password"); e == nil {
		t.Fatal("disabled account logged in")
	}
}
