// Package auth implements identity use cases using consumer-owned ports.
package auth

import (
	"context"
	"errors"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"strings"
	"time"
)

var ErrDenied = domain.ErrDenied
var ErrNotFound = errors.New("identity record unavailable")

func lookupError(e error) error {
	if errors.Is(e, ErrNotFound) {
		return ErrDenied
	}
	return e
}

var ErrInvalid = errors.New("invalid authentication request")

type Service struct {
	access      *access.Service
	tx          transaction.Runner
	repo        Repository
	audit       Audit
	password    Password
	otp         TOTP
	secrets     SecretStore
	now         Clock
	dummy       string
	credentials Credentials
}

func New(tx transaction.Runner, r Repository, a Audit, p Password, o TOTP, se SecretStore, now Clock, credentials Credentials) *Service {
	if now == nil {
		now = time.Now
	}
	dummy, _ := p.Hash("unusable dummy authentication password")
	return &Service{tx: tx, repo: r, audit: a, password: p, otp: o, secrets: se, now: now, dummy: dummy, credentials: credentials}
}
func validPassword(p string) bool { return len(p) >= 15 && len(p) <= 1024 }
func (s *Service) within(ctx context.Context, fn func(transaction.Scope) error) error {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.tx.Within(c, func(sc transaction.Scope) error {
		if e := s.repo.Lock(sc); e != nil {
			return e
		}
		return fn(sc)
	})
}
func (s *Service) event(sc transaction.Scope, action, id string) error {
	eid, e := s.credentials.NewID()
	if e != nil {
		return e
	}
	return s.audit.Append(sc, audit.Event{ID: eid, Action: action, ActorID: id, Payload: []byte(`{}`)})
}
func (s *Service) newInvitation(a *domain.Account) (EnrollmentChallenge, error) {
	token, e := s.credentials.Random()
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	seed, uri, e := s.otp.Generate(a.Name)
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	cipher, e := s.secrets.Seal("identity/totp/"+a.ID, []byte(seed))
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	a.Seed = cipher
	a.InviteHash = s.credentials.Digest(token)
	a.InviteExpires = s.now().Add(15 * time.Minute)
	return EnrollmentChallenge{token, uri, a.InviteExpires}, nil
}

// Bootstrap creates only the first account, or rotates an expired first-account invitation.
// The caller must display the result once via a local authorized initialization channel.
func (s *Service) Bootstrap(ctx context.Context, name string) (EnrollmentChallenge, error) {
	var out EnrollmentChallenge
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name {
		return out, ErrInvalid
	}
	e := s.within(ctx, func(sc transaction.Scope) error {
		empty, e := s.repo.Empty(sc)
		if e != nil {
			return e
		}
		if !empty {
			// Only the offline isolated restorer can arm this one-shot gate.
			// Fresh bootstrap creates a new account; disabled restored accounts
			// never regain authentication through a new TOTP seed.
			if recovery, ok := s.repo.(interface {
				ConsumeRecoveryBootstrap(transaction.Scope) (bool, error)
			}); ok {
				ready, err := recovery.ConsumeRecoveryBootstrap(sc)
				if err != nil {
					return err
				}
				empty = ready
			}
		}
		if !empty {
			a, e := s.repo.AccountByName(sc, name)
			if e != nil {
				return lookupError(e)
			}
			if a.State != domain.Pending || a.PasswordHash != "" || s.now().Before(a.InviteExpires) {
				return ErrDenied
			}
			out, e = s.newInvitation(&a)
			if e != nil {
				return e
			}
			if e = s.repo.SaveAccount(sc, a); e != nil {
				return e
			}
			return s.event(sc, "identity.bootstrap.rotated", a.ID)
		}
		id, e := s.credentials.NewID()
		if e != nil {
			return e
		}
		a := domain.Account{ID: id, Name: name, State: domain.Pending, Role: domain.Admin, AuthVersion: 1, LastStep: -1}
		out, e = s.newInvitation(&a)
		if e != nil {
			return e
		}
		if e = s.repo.CreateAccount(sc, a); e != nil {
			return e
		}
		return s.event(sc, "identity.bootstrap.created", a.ID)
	})
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	return out, nil
}
func (s *Service) EnrollTOTP(ctx context.Context, inviteID, password, code string) (EnrollmentResult, error) {
	var out EnrollmentResult
	if len(inviteID) != 43 || !validPassword(password) {
		return out, ErrInvalid
	}
	hash, e := s.password.Hash(password)
	if e != nil {
		return out, e
	}
	denied := false
	e = s.within(ctx, func(sc transaction.Scope) error {
		a, e := s.repo.AccountByInvite(sc, s.credentials.Digest(inviteID))
		if e != nil {
			return lookupError(e)
		}
		now := s.now()
		if a.CanEnroll(s.credentials.Digest(inviteID), now) != nil {
			return ErrDenied
		}
		plain, e := s.secrets.Open("identity/totp/"+a.ID, a.Seed)
		if e != nil {
			return e
		}
		step, e := s.otp.Verify(string(plain), code, now)
		if e != nil {
			a.Failure(now)
			denied = true
			return s.repo.SaveAccount(sc, a)
		}
		if e = a.Enroll(step); e != nil {
			return e
		}
		a.PasswordHash = hash
		a.Success()
		hashes := make([]string, 10)
		out.RecoveryCodes = make([]string, 10)
		for j := range hashes {
			token, e := s.credentials.Random()
			if e != nil {
				return e
			}
			out.RecoveryCodes[j] = token
			hashes[j] = s.credentials.Digest(token)
		}
		if e = s.repo.ReplaceRecovery(sc, a.ID, hashes); e != nil {
			return e
		}
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		return s.event(sc, "identity.totp.enrolled", a.ID)
	})
	if e != nil {
		return EnrollmentResult{}, e
	}
	if denied {
		return EnrollmentResult{}, ErrDenied
	}
	return out, nil
}
func (s *Service) BeginLogin(ctx context.Context, name, password string) (LoginChallenge, error) {
	var out LoginChallenge
	if len(name) > 128 || len(password) > 1024 {
		return out, ErrDenied
	}
	denied := false
	e := s.within(ctx, func(sc transaction.Scope) error {
		a, e := s.repo.AccountByName(sc, name)
		if e != nil {
			if errors.Is(e, ErrNotFound) {
				s.password.Verify(s.dummy, password)
			}
			return lookupError(e)
		}
		now := s.now()
		if now.Before(a.LockedUntil) {
			return ErrDenied
		}
		ok, upgrade := s.password.Verify(a.PasswordHash, password)
		if !ok || a.CanManage() != nil {
			a.Failure(now)
			denied = true
			return s.repo.SaveAccount(sc, a)
		}
		// Password proof alone must not reset the account-wide second-factor failure budget.
		if upgrade {
			a.PasswordHash, e = s.password.Hash(password)
			if e != nil {
				return e
			}
		}
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		token, e := s.credentials.Random()
		if e != nil {
			return e
		}
		out = LoginChallenge{token, now.Add(5 * time.Minute)}
		return s.repo.SaveChallenge(sc, domain.Challenge{Hash: s.credentials.Digest(token), AccountID: a.ID, AuthVersion: a.AuthVersion, Expires: out.Expires})
	})
	if e != nil {
		return LoginChallenge{}, e
	}
	if denied {
		return LoginChallenge{}, ErrDenied
	}
	return out, nil
}
func (s *Service) FinishLogin(ctx context.Context, challengeID, code string) (Session, error) {
	var out Session
	if len(challengeID) != 43 {
		return out, ErrDenied
	}
	denied := false
	e := s.within(ctx, func(sc transaction.Scope) error {
		c, e := s.repo.Challenge(sc, s.credentials.Digest(challengeID))
		if e != nil {
			return lookupError(e)
		}
		a, e := s.repo.AccountByID(sc, c.AccountID)
		if e != nil {
			return lookupError(e)
		}
		now := s.now()
		if c.Valid(now, a.AuthVersion) != nil || a.CanManage() != nil || now.Before(a.LockedUntil) {
			return ErrDenied
		}
		seed, e := s.secrets.Open("identity/totp/"+a.ID, a.Seed)
		if e != nil {
			return e
		}
		step, e := s.otp.Verify(string(seed), code, now)
		if e != nil || a.UseTOTP(step) != nil {
			c.Attempts++
			a.Failure(now)
			denied = true
			if e = s.repo.SaveAccount(sc, a); e != nil {
				return e
			}
			return s.repo.SaveChallenge(sc, c)
		}
		c.Consumed = true
		a.Success()
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		if e = s.repo.SaveChallenge(sc, c); e != nil {
			return e
		}
		token, e := s.credentials.Random()
		if e != nil {
			return e
		}
		csrf, e := s.credentials.Random()
		if e != nil {
			return e
		}
		id, e := s.credentials.NewID()
		if e != nil {
			return e
		}
		expires := now.Add(8 * time.Hour)
		if e = s.repo.CreateSession(sc, domain.Session{ID: id, AccountID: a.ID, TokenHash: s.credentials.Digest(token), CSRFHash: s.credentials.Digest(csrf), AuthVersion: a.AuthVersion, Expires: expires}); e != nil {
			return e
		}
		out = Session{token, csrf, expires, Actor{UserID: a.ID, AuthVersion: a.AuthVersion, CredentialKind: "session", CredentialID: id, Role: a.Role}}
		return s.event(sc, "identity.login", a.ID)
	})
	if e != nil {
		return Session{}, e
	}
	if denied {
		return Session{}, ErrDenied
	}
	return out, nil
}
func (s *Service) Recover(ctx context.Context, name, password, recoveryCode string) (EnrollmentChallenge, error) {
	var out EnrollmentChallenge
	if len(name) > 128 || len(password) > 1024 || len(recoveryCode) != 43 {
		return out, ErrDenied
	}
	denied := false
	e := s.within(ctx, func(sc transaction.Scope) error {
		a, e := s.repo.AccountByName(sc, name)
		if e != nil {
			if errors.Is(e, ErrNotFound) {
				s.password.Verify(s.dummy, password)
			}
			return lookupError(e)
		}
		now := s.now()
		if a.CanRecover() != nil || now.Before(a.LockedUntil) {
			return ErrDenied
		}
		ok, _ := s.password.Verify(a.PasswordHash, password)
		if !ok {
			a.Failure(now)
			denied = true
			return s.repo.SaveAccount(sc, a)
		}
		used, e := s.repo.ConsumeRecovery(sc, a.ID, s.credentials.Digest(recoveryCode))
		if e != nil {
			return e
		}
		r := domain.Recovery{Consumed: !used}
		if r.Consume(a) != nil {
			a.Failure(now)
			denied = true
			return s.repo.SaveAccount(sc, a)
		}
		a.Reset()
		out, e = s.newInvitation(&a)
		if e != nil {
			return e
		}
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		return s.event(sc, "identity.recovery", a.ID)
	})
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	if denied {
		return EnrollmentChallenge{}, ErrDenied
	}
	return out, nil
}
