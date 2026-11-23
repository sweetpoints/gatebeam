package pkiaccess

import (
	"context"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	pki "gatebeam/internal/modules/pki/application"
	"gatebeam/internal/platform/transaction"
)

// Queries require a current interactive administrator, without consuming MFA.
type Queries struct {
	Access       *access.Service
	Actor        identity.Actor
	Transactions transaction.Runner
}

func (q Queries) Within(ctx context.Context, a pki.ActorRef, fn func(transaction.Scope) error) error {
	if a.UserID != q.Actor.UserID || a.AuthVersion != q.Actor.AuthVersion || a.CredentialID != q.Actor.CredentialID || a.CredentialKind != string(q.Actor.CredentialKind) || a.CredentialKind != "session" {
		return pki.ErrGrantDenied
	}
	return q.Transactions.Within(ctx, func(sc transaction.Scope) error {
		if e := q.Access.RequireWithin(sc, q.Actor, identity.Manage, nil); e != nil {
			return pki.ErrGrantDenied
		}
		return fn(sc)
	})
}
