package auth

import (
	"context"
	app "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/platform/transaction"
	"strings"
	"time"
)

func (s *Service) SetAccess(a *access.Service) { s.access = a }
func (s *Service) AuthenticateToken(ctx context.Context, token string) (Actor, error) {
	if s.access == nil {
		return Actor{}, ErrDenied
	}
	a, e := s.access.AuthenticateToken(ctx, token)
	return a, lookupError(e)
}

// sensitive consumes fresh single-use TOTP with the account-wide failure budget.
// Invalid proofs commit their failure count. Successful proofs roll back with
// the requested operation and its audit, so a failed transaction leaks no secret.
func (s *Service) sensitive(ctx context.Context, actor Actor, code string, admin bool, fn func(transaction.Scope) error) error {
	if s.access == nil || actor.CredentialKind != app.SessionCredential {
		return ErrDenied
	}
	denied := false
	e := s.within(ctx, func(sc transaction.Scope) error {
		if admin {
			if e := s.access.ManageWithin(sc, actor); e != nil {
				return lookupError(e)
			}
		} else {
			if _, e := s.repo.AccountByID(sc, actor.UserID); e != nil {
				return lookupError(e)
			}
			if e := s.access.ValidateInteractiveWithin(sc, actor); e != nil {
				return lookupError(e)
			}
		}
		a, e := s.repo.AccountByID(sc, actor.UserID)
		if e != nil {
			return lookupError(e)
		}
		now := s.now()
		if now.Before(a.LockedUntil) {
			return ErrDenied
		}
		seed, e := s.secrets.Open("identity/totp/"+a.ID, a.Seed)
		if e != nil {
			return e
		}
		step, e := s.otp.Verify(string(seed), code, now)
		if e != nil || a.UseTOTP(step) != nil {
			a.Failure(now)
			denied = true
			return s.repo.SaveAccount(sc, a)
		}
		a.Success()
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		return fn(sc)
	})
	if e != nil {
		return e
	}
	if denied {
		return ErrDenied
	}
	return nil
}
func (s *Service) CreateAccount(ctx context.Context, actor Actor, code, name string, role app.Role) (EnrollmentChallenge, error) {
	var out EnrollmentChallenge
	if strings.TrimSpace(name) != name || len(name) < 1 || len(name) > 128 || !role.Valid() {
		return out, ErrInvalid
	}
	e := s.sensitive(ctx, actor, code, true, func(sc transaction.Scope) error {
		id, e := s.credentials.NewID()
		if e != nil {
			return e
		}
		a := domain.Account{ID: id, Name: name, State: domain.Pending, Role: role, AuthVersion: 1, LastStep: -1}
		out, e = s.newInvitation(&a)
		if e != nil {
			return e
		}
		if e = s.repo.CreateAccount(sc, a); e != nil {
			return e
		}
		return s.access.EventWithin(sc, actor, "identity.account.created", id)
	})
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	return out, nil
}
func (s *Service) ResetAccount(ctx context.Context, actor Actor, code, id string) (EnrollmentChallenge, error) {
	var out EnrollmentChallenge
	e := s.sensitive(ctx, actor, code, true, func(sc transaction.Scope) error {
		a, e := s.repo.AccountByID(sc, id)
		if e != nil {
			return lookupError(e)
		}
		a.Reset()
		a.PasswordHash = ""
		out, e = s.newInvitation(&a)
		if e != nil {
			return e
		}
		if e = s.repo.ReplaceRecovery(sc, id, nil); e != nil {
			return e
		}
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		return s.access.EventWithin(sc, actor, "identity.account.reset", id)
	})
	if e != nil {
		return EnrollmentChallenge{}, e
	}
	return out, nil
}
func (s *Service) DisableAccount(ctx context.Context, actor Actor, code, id string) error {
	return s.sensitive(ctx, actor, code, true, func(sc transaction.Scope) error {
		a, e := s.repo.AccountByID(sc, id)
		if e != nil {
			return lookupError(e)
		}
		a.State = domain.Disabled
		a.AuthVersion++
		if e = s.repo.SaveAccount(sc, a); e != nil {
			return e
		}
		return s.access.EventWithin(sc, actor, "identity.account.disabled", id)
	})
}
func (s *Service) SetAuthority(ctx context.Context, actor Actor, code, id string, role app.Role, grants []domain.Grant) error {
	if grants == nil || len(grants) > 100 {
		return ErrInvalid
	}
	return s.sensitive(ctx, actor, code, true, func(sc transaction.Scope) error { return s.access.SetAuthorityWithin(sc, actor, id, role, grants) })
}

type IssuedToken struct {
	access.TokenView
	Token string `json:"token"`
}

func (s *Service) IssueToken(ctx context.Context, actor Actor, code string, actions, sites []string, expires time.Time) (IssuedToken, error) {
	var out IssuedToken
	e := s.sensitive(ctx, actor, code, false, func(sc transaction.Scope) error {
		v, raw, e := s.access.IssueTokenWithin(sc, actor, actions, sites, expires)
		out = IssuedToken{v, raw}
		return e
	})
	if e != nil {
		return IssuedToken{}, e
	}
	return out, nil
}
func (s *Service) RevokeToken(ctx context.Context, actor Actor, code, id string) error {
	return s.sensitive(ctx, actor, code, false, func(sc transaction.Scope) error { return s.access.RevokeTokenWithin(sc, actor, id) })
}
func (s *Service) Accounts(ctx context.Context, a Actor, l, o int32) ([]access.AccountView, error) {
	if s.access == nil {
		return nil, ErrDenied
	}
	return s.access.Accounts(ctx, a, l, o)
}
func (s *Service) Tokens(ctx context.Context, a Actor, l, o int32) ([]access.TokenView, error) {
	if s.access == nil {
		return nil, ErrDenied
	}
	return s.access.Tokens(ctx, a, l, o)
}
func (s *Service) Audit(ctx context.Context, a Actor, l, o int32) ([]access.AuditView, error) {
	if s.access == nil {
		return nil, ErrDenied
	}
	return s.access.Audit(ctx, a, l, o)
}

// AdministrativeAction is the narrow composition contract for a security action
// owned by another module. Current administrator authority, interactive session,
// and fresh single-use TOTP are checked in the same transaction as fn's writes.
func (s *Service) AdministrativeAction(ctx context.Context, actor Actor, code string, fn func(transaction.Scope) error) error {
	return s.sensitive(ctx, actor, code, true, fn)
}
