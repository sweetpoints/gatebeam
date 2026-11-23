// Package domain owns identity state transitions without storage or protocol dependencies.
package domain

import (
	"errors"
	"time"
)

var ErrDenied = errors.New("authentication denied")

type State string

const (
	Pending  State = "pending"
	Active   State = "active"
	Disabled State = "disabled"
)

type Account struct {
	ID, Name, PasswordHash string
	Role                   Role
	State                  State
	AuthVersion, LastStep  int64
	Seed                   []byte
	InviteHash             string
	InviteExpires          time.Time
	Failures               int32
	LockedUntil            time.Time
}

func (a Account) CanManage() error {
	if a.State != Active {
		return ErrDenied
	}
	return nil
}
func (a *Account) UseTOTP(step int64) error {
	if a.State != Active || step <= a.LastStep {
		return ErrDenied
	}
	a.LastStep = step
	return nil
}
func (a *Account) Enroll(step int64) error {
	if a.State != Pending || step < 0 {
		return ErrDenied
	}
	a.State = Active
	a.LastStep = step
	a.InviteHash = ""
	a.InviteExpires = time.Time{}
	return nil
}
func (a *Account) Reset() {
	a.State = Pending
	a.AuthVersion++
	a.LastStep = -1
	a.Failures = 0
	a.LockedUntil = time.Time{}
}
func (a Account) CanEnroll(hash string, now time.Time) error {
	if a.State != Pending || hash == "" || a.InviteHash != hash || !now.Before(a.InviteExpires) || now.Before(a.LockedUntil) {
		return ErrDenied
	}
	return nil
}
func (a *Account) Failure(now time.Time) {
	a.Failures++
	if a.Failures >= 5 {
		a.LockedUntil = now.Add(15 * time.Minute)
		a.Failures = 0
	}
}
func (a *Account) Success() { a.Failures = 0; a.LockedUntil = time.Time{} }

// CanRecover allows remaining single-use codes to replace a lost/expired reset
// invitation. Initial bootstrap has no password and no recovery authority.
func (a Account) CanRecover() error {
	if a.PasswordHash == "" || (a.State != Active && a.State != Pending) {
		return ErrDenied
	}
	return nil
}
