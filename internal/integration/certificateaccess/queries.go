package certificateaccess

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/platform/transaction"
)

// QuerySecurity authenticates the current credential before freezing references.
// Each resource then requires View on every affected draft and published site.
type QuerySecurity struct {
	*Security
	Transactions transaction.Runner
}

func (s QuerySecurity) Within(ctx context.Context, a app.ActorRef, fn func(transaction.Scope) error) error {
	if a.UserID != s.Actor.UserID || a.AuthVersion != s.Actor.AuthVersion || a.CredentialKind != string(s.Actor.CredentialKind) || a.CredentialID != s.Actor.CredentialID {
		return app.ErrDenied
	}
	return s.Transactions.Within(ctx, func(sc transaction.Scope) error {
		if e := s.Access.GuardWithin(sc, s.Actor); e != nil {
			return queryError(e)
		}
		return fn(sc)
	})
}
func queryError(e error) error {
	if errors.Is(e, access.ErrDenied) {
		return app.ErrDenied
	}
	return e
}
func (s QuerySecurity) RequireWithin(sc transaction.Scope, a app.ActorRef, resources []string) error {
	seen := map[string]bool{}
	for _, id := range resources {
		sites, e := s.Ingress.AffectedSitesWithin(sc, id)
		if e != nil {
			return e
		}
		for _, site := range sites {
			seen[site] = true
		}
	}
	if len(seen) == 0 {
		return queryError(s.Access.RequireWithin(sc, s.Actor, identity.Manage, nil))
	}
	ids := []string{}
	for id := range seen {
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += 100 {
		if e := s.Access.RequireWithin(sc, s.Actor, identity.View, ids[start:min(start+100, len(ids))]); e != nil {
			return queryError(e)
		}
	}
	return nil
}
