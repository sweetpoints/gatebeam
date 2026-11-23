//go:build integration

package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"gatebeam/internal/modules/identity/application/auth"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	otpAdapter "gatebeam/internal/modules/identity/infrastructure/otp"
	"gatebeam/internal/modules/identity/infrastructure/password"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, writers ...auth.Audit) (*auth.Service, *time.Time, *pgxpool.Pool) {
	t.Helper()
	p := testkit.Postgres(t)
	_, e := p.Exec(context.Background(), "TRUNCATE identity_sessions,identity_challenges,identity_recovery,identity_accounts CASCADE")
	if e != nil {
		t.Fatal(e)
	}
	key, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	f := filepath.Join(t.TempDir(), "identity")
	if e = os.WriteFile(f, []byte(key.String()), 0600); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(f)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(30 * time.Second)
	var writer auth.Audit = audit.New()
	if len(writers) > 0 {
		writer = writers[0]
	}
	s := auth.New(postgres.NewRunner(p), repo.New(), writer, password.New(), otpAdapter.New(), se, func() time.Time { return now }, credential.New())
	return s, &now, p
}
func setup(t *testing.T, s *auth.Service, now time.Time) (auth.EnrollmentChallenge, string) {
	t.Helper()
	i, e := s.Bootstrap(context.Background(), "admin")
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(i.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	seed := u.Query().Get("secret")
	if seed == "" {
		t.Fatal("missing seed")
	}
	return i, seed
}
func code(t *testing.T, seed string, now time.Time) string {
	t.Helper()
	c, e := totp.GenerateCode(seed, now)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestEnrollmentCannotAccessManagement(t *testing.T) {
	s, now, _ := fixture(t)
	i, _ := setup(t, s, *now)
	if _, e := s.Authenticate(context.Background(), i.InviteID); e == nil {
		t.Fatal("invitation authenticated")
	}
	if _, e := s.BeginLogin(context.Background(), "admin", "a long enough password"); e == nil {
		t.Fatal("pending login accepted")
	}
}
func TestConcurrentTOTPAndRecoveryReplay(t *testing.T) {
	s, now, _ := fixture(t)
	i, seed := setup(t, s, *now)
	en, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	if len(en.RecoveryCodes) != 10 {
		t.Fatal("recovery codes missing")
	}
	*now = now.Add(30 * time.Second)
	c1, e := s.BeginLogin(context.Background(), "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	c2, e := s.BeginLogin(context.Background(), "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	var n atomic.Int32
	var wg sync.WaitGroup
	for _, c := range []string{c1.ChallengeID, c2.ChallengeID} {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			if _, e := s.FinishLogin(context.Background(), c, code(t, seed, *now)); e == nil {
				n.Add(1)
			}
		}(c)
	}
	wg.Wait()
	if n.Load() != 1 {
		t.Fatalf("TOTP successes %d", n.Load())
	}
	n.Store(0)
	for j := 0; j < 2; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.Recover(context.Background(), "admin", "a long enough password", en.RecoveryCodes[0]); e == nil {
				n.Add(1)
			}
		}()
	}
	wg.Wait()
	if n.Load() != 1 {
		t.Fatalf("recovery successes %d", n.Load())
	}
}
func TestResetInvalidatesSessionsAndRequiresEnrollment(t *testing.T) {
	s, now, _ := fixture(t)
	i, seed := setup(t, s, *now)
	en, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	c, e := s.BeginLogin(context.Background(), "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	session, e := s.FinishLogin(context.Background(), c.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	actor, e := s.Authenticate(context.Background(), session.Token)
	if e != nil || actor.CredentialID == "" || actor.AuthVersion < 1 {
		t.Fatal("credential reference lost", e)
	}
	r, e := s.Recover(context.Background(), "admin", "a long enough password", en.RecoveryCodes[0])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(context.Background(), session.Token); e == nil {
		t.Fatal("old session accepted")
	}
	if _, e = s.BeginLogin(context.Background(), "admin", "a long enough password"); e == nil {
		t.Fatal("pending reset logged in")
	}
	u, _ := url.Parse(r.ProvisioningURI)
	if _, e = s.EnrollTOTP(context.Background(), r.InviteID, "replacement strong password", code(t, u.Query().Get("secret"), *now)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(context.Background(), session.Token); e == nil {
		t.Fatal("old session resurrected")
	}
}

type failAudit struct{ fail bool }

func (a *failAudit) Append(sc transaction.Scope, e audit.Event) error {
	if a.fail {
		return errors.New("audit failed")
	}
	return audit.New().Append(sc, e)
}
func TestAuditFailureRollsBackBootstrapAndEnrollment(t *testing.T) {
	writer := &failAudit{true}
	s, now, p := fixture(t, writer)
	if _, e := s.Bootstrap(context.Background(), "admin"); e == nil {
		t.Fatal("audit error ignored")
	}
	var n int
	if e := p.QueryRow(context.Background(), "SELECT count(*) FROM identity_accounts").Scan(&n); e != nil || n != 0 {
		t.Fatal("account escaped rollback", n, e)
	}
	writer.fail = false
	i, seed := setup(t, s, *now)
	writer.fail = true
	if out, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now)); e == nil || len(out.RecoveryCodes) != 0 {
		t.Fatal("failed enrollment disclosed codes")
	}
	var state string
	if e := p.QueryRow(context.Background(), "SELECT state FROM identity_accounts").Scan(&state); e != nil || state != "pending" {
		t.Fatal("enrollment escaped rollback", state, e)
	}
	writer.fail = false
	if _, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal("invite was consumed on rollback", e)
	}
}
func TestAttemptsExpiryLogoutAndSecretStorage(t *testing.T) {
	s, now, p := fixture(t)
	i, seed := setup(t, s, *now)
	var storedHash string
	var cipher []byte
	if e := p.QueryRow(context.Background(), "SELECT invite_hash,seed FROM identity_accounts").Scan(&storedHash, &cipher); e != nil {
		t.Fatal(e)
	}
	if storedHash == i.InviteID || string(cipher) == seed {
		t.Fatal("plaintext bearer or seed stored")
	}
	en, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	var raw bool
	if e = p.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM identity_recovery WHERE hash=$1)", en.RecoveryCodes[0]).Scan(&raw); e != nil || raw {
		t.Fatal("raw recovery stored", e)
	}
	*now = now.Add(30 * time.Second)
	c, e := s.BeginLogin(context.Background(), "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	for j := 0; j < 5; j++ {
		if _, e = s.FinishLogin(context.Background(), c.ChallengeID, "bad"); e == nil {
			t.Fatal("invalid OTP accepted")
		}
	}
	var attempts int
	var locked time.Time
	if e = p.QueryRow(context.Background(), "SELECT attempts FROM identity_challenges").Scan(&attempts); e != nil || attempts != 5 {
		t.Fatal("challenge failures not committed", attempts, e)
	}
	if e = p.QueryRow(context.Background(), "SELECT locked_until FROM identity_accounts").Scan(&locked); e != nil || !locked.After(*now) {
		t.Fatal("account lock not committed", locked, e)
	}
	if _, e = s.BeginLogin(context.Background(), "admin", "a long enough password"); e == nil {
		t.Fatal("new challenge bypassed account lock")
	}
	*now = now.Add(16 * time.Minute)
	if _, e = s.FinishLogin(context.Background(), c.ChallengeID, code(t, seed, *now)); e == nil {
		t.Fatal("exhausted expired challenge accepted")
	}
	c, e = s.BeginLogin(context.Background(), "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	session, e := s.FinishLogin(context.Background(), c.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.AuthenticateWrite(context.Background(), session.Token, "invalid"); e == nil {
		t.Fatal("missing CSRF accepted")
	}
	if _, e = s.AuthenticateWrite(context.Background(), session.Token, session.CSRFToken); e != nil {
		t.Fatal(e)
	}
	if e = s.Logout(context.Background(), session.Token, "invalid"); e == nil {
		t.Fatal("logout bypassed CSRF")
	}
	if e = s.Logout(context.Background(), session.Token, session.CSRFToken); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(context.Background(), session.Token); e == nil {
		t.Fatal("logged-out session accepted")
	}
	if _, e = s.Bootstrap(context.Background(), "another-admin"); e == nil {
		t.Fatal("second bootstrap accepted")
	}
}

func TestRecoveryAndPasswordFailuresPersist(t *testing.T) {
	s, now, p := fixture(t)
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	for j := 0; j < 5; j++ {
		if _, e := s.Recover(context.Background(), "admin", "a long enough password", strings.Repeat("A", 43)); e == nil {
			t.Fatal("invalid recovery accepted")
		}
	}
	var locked time.Time
	if e := p.QueryRow(context.Background(), "SELECT locked_until FROM identity_accounts").Scan(&locked); e != nil || !locked.After(*now) {
		t.Fatal("recovery attempts rolled back", e)
	}
	if _, e := s.BeginLogin(context.Background(), "admin", "a long enough password"); e == nil {
		t.Fatal("login bypassed recovery lock")
	}
	*now = now.Add(16 * time.Minute)
	for j := 0; j < 5; j++ {
		if _, e := s.BeginLogin(context.Background(), "admin", "wrong"); e == nil {
			t.Fatal("wrong password accepted")
		}
	}
	if e := p.QueryRow(context.Background(), "SELECT locked_until FROM identity_accounts").Scan(&locked); e != nil || !locked.After(*now) {
		t.Fatal("password attempts rolled back", e)
	}
}

func TestRecoveryResponseLossAndExpiredInvitationResume(t *testing.T) {
	s, now, _ := fixture(t)
	i, seed := setup(t, s, *now)
	en, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	first, e := s.Recover(context.Background(), "admin", "a long enough password", en.RecoveryCodes[0])
	if e != nil {
		t.Fatal(e)
	}
	second, e := s.Recover(context.Background(), "admin", "a long enough password", en.RecoveryCodes[1])
	if e != nil {
		t.Fatal("response loss could not resume", e)
	}
	u, _ := url.Parse(first.ProvisioningURI)
	if _, e = s.EnrollTOTP(context.Background(), first.InviteID, "replacement strong password", code(t, u.Query().Get("secret"), *now)); e == nil {
		t.Fatal("old invitation accepted")
	}
	*now = now.Add(16 * time.Minute)
	u, _ = url.Parse(second.ProvisioningURI)
	if _, e = s.EnrollTOTP(context.Background(), second.InviteID, "replacement strong password", code(t, u.Query().Get("secret"), *now)); e == nil {
		t.Fatal("expired invitation accepted")
	}
	third, e := s.Recover(context.Background(), "admin", "a long enough password", en.RecoveryCodes[2])
	if e != nil {
		t.Fatal("expired invitation could not resume", e)
	}
	u, _ = url.Parse(third.ProvisioningURI)
	if _, e = s.EnrollTOTP(context.Background(), third.InviteID, "replacement strong password", code(t, u.Query().Get("secret"), *now)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Recover(context.Background(), "admin", "replacement strong password", en.RecoveryCodes[3]); e == nil {
		t.Fatal("old recovery code survived reenrollment")
	}
}

func TestNewChallengesCannotResetTOTPAttemptBudget(t *testing.T) {
	s, now, _ := fixture(t)
	i, seed := setup(t, s, *now)
	if _, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now)); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	for j := 0; j < 5; j++ {
		c, e := s.BeginLogin(context.Background(), "admin", "a long enough password")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.FinishLogin(context.Background(), c.ChallengeID, "bad"); e == nil {
			t.Fatal("invalid TOTP accepted")
		}
	}
	if _, e := s.BeginLogin(context.Background(), "admin", "a long enough password"); e == nil {
		t.Fatal("new challenges erased accumulated TOTP failures")
	}
}

func TestStorageFailureIsNotReportedAsBadCredentials(t *testing.T) {
	s, _, p := fixture(t)
	if _, e := p.Exec(context.Background(), "DROP TABLE identity_accounts CASCADE"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.BeginLogin(context.Background(), "admin", "a long enough password"); e == nil || errors.Is(e, auth.ErrDenied) {
		t.Fatal("storage failure disguised as authentication denial", e)
	}
}

func TestResourceIDsAreUUIDsInPersistenceAndSessionAPI(t *testing.T) {
	s, now, p := fixture(t)
	i, seed := setup(t, s, *now)
	enrollment, e := s.EnrollTOTP(context.Background(), i.InviteID, "a long enough password", code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(30 * time.Second)
	challenge, e := s.BeginLogin(context.Background(), "admin", "a long enough password")
	if e != nil {
		t.Fatal(e)
	}
	session, e := s.FinishLogin(context.Background(), challenge.ChallengeID, code(t, seed, *now))
	if e != nil {
		t.Fatal(e)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for _, table := range []string{"identity_accounts", "identity_sessions", "audit"} {
		rows, e := p.Query(context.Background(), "SELECT id FROM "+table)
		if e != nil {
			t.Fatal(e)
		}
		n := 0
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				t.Fatal(e)
			}
			if !uuid.MatchString(id) {
				t.Errorf("%s resource ID is not UUIDv4: %q", table, id)
			}
			n++
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		if n == 0 {
			t.Fatal("missing persisted IDs", table)
		}
	}
	handler, e := authHTTP.New(s, p.Ping, authHTTP.Config{Origin: "https://admin.example", Production: true})
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("GET", "/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: session.Token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var actor auth.Actor
	if e = json.Unmarshal(response.Body.Bytes(), &actor); e != nil {
		t.Fatal(e)
	}
	if !uuid.MatchString(actor.UserID) || !uuid.MatchString(actor.CredentialID) {
		t.Errorf("session API resource references must be UUIDv4: %+v", actor)
	}
	for _, value := range enrollment.RecoveryCodes {
		if len(value) != 43 || uuid.MatchString(value) {
			t.Error("recovery bearer entropy/encoding changed")
		}
	}
	for name, value := range map[string]string{"invite": i.InviteID, "challenge": challenge.ChallengeID, "session bearer": session.Token, "CSRF": session.CSRFToken} {
		if len(value) != 43 || uuid.MatchString(value) {
			t.Errorf("%s no longer high-entropy bearer", name)
		}
	}
}
