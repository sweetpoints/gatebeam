package domain

import (
	"testing"
	"time"
)

func TestPendingReplayAndReset(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := Account{ID: "account", State: Pending, AuthVersion: 1, LastStep: -1}
	if a.CanManage() != ErrDenied {
		t.Fatal("pending account managed")
	}
	if e := a.Enroll(60000000); e != nil {
		t.Fatal(e)
	}
	if e := a.UseTOTP(60000000); e != ErrDenied {
		t.Fatal("OTP replay")
	}
	if e := a.UseTOTP(60000001); e != nil {
		t.Fatal(e)
	}
	s := Session{AccountID: a.ID, AuthVersion: a.AuthVersion, Expires: now.Add(time.Hour)}
	if e := s.Validate(a, now); e != nil {
		t.Fatal(e)
	}
	a.Reset()
	if e := s.Validate(a, now); e != ErrDenied {
		t.Fatal("reset session accepted")
	}
	if a.AuthVersion != 2 || a.State != Pending {
		t.Fatal("reset transition")
	}
	if e := a.Enroll(2); e != nil {
		t.Fatal(e)
	}
	if e := s.Validate(a, now); e != ErrDenied {
		t.Fatal("old session resurrected")
	}
}
func TestChallengeExpiryAndAttempts(t *testing.T) {
	now := time.Unix(100, 0)
	c := Challenge{Expires: now, AuthVersion: 1}
	if c.Valid(now, 1) == nil {
		t.Fatal("expiry accepted")
	}
	c.Expires = now.Add(time.Minute)
	c.Attempts = 5
	if c.Valid(now, 1) == nil {
		t.Fatal("exhausted challenge accepted")
	}
	c.Attempts = 0
	if c.Valid(now, 2) == nil {
		t.Fatal("old auth version accepted")
	}
}

func TestRecoveryPendingCanResumeWithoutManagement(t *testing.T) {
	a := Account{ID: "a", State: Active, PasswordHash: "hash", AuthVersion: 1}
	a.Reset()
	if e := a.CanRecover(); e != nil {
		t.Fatal(e)
	}
	if e := a.CanManage(); e == nil {
		t.Fatal("recovery pending managed")
	}
	r := Recovery{}
	if e := r.Consume(a); e != nil {
		t.Fatal("unused code rejected", e)
	}
	if e := r.Consume(a); e == nil {
		t.Fatal("code reused")
	}
}
