package http

import (
	"context"
	"errors"
	"gatebeam/internal/modules/identity/application/auth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type authStub struct{}

func (authStub) BeginLogin(context.Context, string, string) (auth.LoginChallenge, error) {
	return auth.LoginChallenge{ChallengeID: "challenge"}, nil
}
func (authStub) FinishLogin(context.Context, string, string) (auth.Session, error) {
	return auth.Session{Token: "secret-session", CSRFToken: "secret-csrf"}, nil
}
func (authStub) EnrollTOTP(context.Context, string, string, string) (auth.EnrollmentResult, error) {
	return auth.EnrollmentResult{}, auth.ErrDenied
}
func (authStub) Recover(context.Context, string, string, string) (auth.EnrollmentChallenge, error) {
	return auth.EnrollmentChallenge{}, auth.ErrDenied
}
func (authStub) Authenticate(context.Context, string) (auth.Actor, error) {
	return auth.Actor{}, auth.ErrDenied
}
func (authStub) Logout(context.Context, string, string) error { return auth.ErrDenied }
func TestOriginCookieAndPendingDenied(t *testing.T) {
	h, e := New(authStub{}, func(context.Context) error { return nil }, Config{Origin: "https://admin.example", Production: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, origin := range []string{"", "https://evil.example", "null"} {
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"name":"admin","password":"secret"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("origin %q: %d", origin, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/auth/login/finish", strings.NewReader(`{"challenge_id":"challenge","code":"123456"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://admin.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie", cookies)
	}
	if strings.Contains(w.Body.String(), "secret-session") {
		t.Fatal("token leaked in JSON")
	}
	r = httptest.NewRequest("GET", "/auth/session", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: "invitation"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("pending credential accepted", w.Code)
	}
}
func TestReadinessRecoversAndLivenessIndependent(t *testing.T) {
	down := false
	h, e := New(authStub{}, func(c context.Context) error {
		if _, ok := c.Deadline(); !ok {
			t.Error("unbounded DB probe")
		}
		if down {
			return errors.New("private DB password")
		}
		return nil
	}, Config{Origin: "http://localhost:8080"})
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []int{200, 503, 200} {
		down = want == 503
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		if w.Code != want || strings.Contains(w.Body.String(), "password") {
			t.Fatal(w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/livez", nil))
		if w.Code != 200 {
			t.Fatal("DB affected liveness")
		}
	}
}
func TestRESTErrorContractAndFrameworkStatus(t *testing.T) {
	h, e := New(authStub{}, func(context.Context) error { return nil }, Config{Origin: "https://admin.example", Production: true})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "/missing", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 || !strings.Contains(w.Body.String(), `"request_id"`) || !strings.Contains(w.Body.String(), `"code"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
