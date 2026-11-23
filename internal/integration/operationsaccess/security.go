// Package operationsaccess maps the complete authenticated credential to owner ports.
package operationsaccess

import (
	"gatebeam/internal/modules/backup/application"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/platform/transaction"
)

type Backup struct{ Access *access.Service }

func (s Backup) RequireWithin(sc transaction.Scope, a application.ActorRef) error {
	if e := s.Access.RequireWithin(sc, identity.Actor{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: identity.CredentialKind(a.CredentialKind), CredentialID: a.CredentialID}, identity.Manage, nil); e != nil {
		return application.ErrDenied
	}
	return nil
}
