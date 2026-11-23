// Package statistics maps current identity authorization to statistics queries.
package statistics

import (
	"errors"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/platform/transaction"
)

type Security struct{ Access *access.Service }

func (s Security) RequireWithin(sc transaction.Scope, a stats.ActorRef, ids []string) error {
	// Identity.RequireWithin locks identity first, then its ingress catalog freezes
	// the current site/group graph. Both locks cover the owner's stats read.
	e := s.Access.RequireWithin(sc, identity.Actor{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: identity.CredentialKind(a.CredentialKind), CredentialID: a.CredentialID}, identity.View, ids)
	if errors.Is(e, access.ErrDenied) {
		return stats.ErrDenied
	}
	return e
}

// GuardWithin validates the complete current credential even when a list is empty.
func (s Security) GuardWithin(sc transaction.Scope, a stats.ActorRef) error {
	if e := s.Access.GuardWithin(sc, identity.Actor{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: identity.CredentialKind(a.CredentialKind), CredentialID: a.CredentialID}); e != nil {
		return stats.ErrDenied
	}
	return nil
}
