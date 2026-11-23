// Package pkiaccess maps identity's fresh administrative transaction to PKI's
// consumer-owned port. The request's proof never enters an ActorRef or context.
package pkiaccess

import (
	"context"
	"errors"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/auth"
	pki "gatebeam/internal/modules/pki/application"
	"gatebeam/internal/platform/transaction"
)

type Security struct {
	identity *auth.Service
	actor    identity.Actor
	code     string
}

func New(identity *auth.Service, actor identity.Actor, code string) *Security {
	return &Security{identity, actor, code}
}
func (s *Security) Within(ctx context.Context, a pki.ActorRef, fn func(transaction.Scope) error) error {
	if s.identity == nil || a.UserID != s.actor.UserID || a.AuthVersion != s.actor.AuthVersion || a.CredentialID != s.actor.CredentialID || a.CredentialKind != string(s.actor.CredentialKind) || a.CredentialKind != "session" {
		return pki.ErrGrantDenied
	}
	e := s.identity.AdministrativeAction(ctx, s.actor, s.code, fn)
	if errors.Is(e, auth.ErrDenied) || errors.Is(e, auth.ErrNotFound) {
		return pki.ErrGrantDenied
	}
	return e
}
