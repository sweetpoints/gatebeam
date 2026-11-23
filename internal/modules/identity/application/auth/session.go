package auth

import (
	"context"
	"gatebeam/internal/platform/transaction"
)

func (s *Service) Authenticate(ctx context.Context, token string) (Actor, error) {
	return s.authenticate(ctx, token, "", false)
}
func (s *Service) AuthenticateWrite(ctx context.Context, token, csrf string) (Actor, error) {
	return s.authenticate(ctx, token, csrf, true)
}
func (s *Service) authenticate(ctx context.Context, token, csrf string, write bool) (Actor, error) {
	var actor Actor
	if len(token) != 43 {
		return actor, ErrDenied
	}
	e := s.within(ctx, func(sc transaction.Scope) error {
		session, e := s.repo.Session(sc, s.credentials.Digest(token))
		if e != nil {
			return lookupError(e)
		}
		a, e := s.repo.AccountByID(sc, session.AccountID)
		if e != nil {
			return lookupError(e)
		}
		if session.Validate(a, s.now()) != nil {
			return ErrDenied
		}
		if write && (len(csrf) != 43 || !s.credentials.Equal(s.credentials.Digest(csrf), session.CSRFHash)) {
			return ErrDenied
		}
		actor = Actor{UserID: a.ID, AuthVersion: a.AuthVersion, CredentialKind: "session", CredentialID: session.ID, Role: a.Role}
		return nil
	})
	return actor, e
}
func (s *Service) Logout(ctx context.Context, token, csrf string) error {
	if len(token) != 43 || len(csrf) != 43 {
		return ErrDenied
	}
	return s.within(ctx, func(sc transaction.Scope) error {
		session, e := s.repo.Session(sc, s.credentials.Digest(token))
		if e != nil {
			return lookupError(e)
		}
		a, e := s.repo.AccountByID(sc, session.AccountID)
		if e != nil {
			return lookupError(e)
		}
		if session.Validate(a, s.now()) != nil || !s.credentials.Equal(s.credentials.Digest(csrf), session.CSRFHash) {
			return ErrDenied
		}
		if e = s.repo.RevokeSession(sc, session.ID); e != nil {
			return e
		}
		return s.event(sc, "identity.logout", a.ID)
	})
}
