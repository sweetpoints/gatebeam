// Package certificateaccess maps current identity and ingress ownership contracts.
package certificateaccess

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/application/auth"
	ingress "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/platform/transaction"
)

var ErrDenied = app.ErrDenied

// Security is bound per management request to a trusted authenticated Actor and
// fresh MFA proof. The CA signer/root identity is absent from this capability.
type Security struct {
	Authentication *auth.Service
	Access         *access.Service
	Ingress        *ingress.Service
	Actor          identity.Actor
	Code           string
}

func (s *Security) Within(ctx context.Context, a app.ActorRef, fn func(transaction.Scope) error) error {
	if s.Authentication == nil || a.UserID != s.Actor.UserID || a.AuthVersion != s.Actor.AuthVersion || a.CredentialID != s.Actor.CredentialID || a.CredentialKind != string(s.Actor.CredentialKind) {
		return ErrDenied
	}
	e := s.Authentication.AdministrativeAction(ctx, s.Actor, s.Code, fn)
	if errors.Is(e, auth.ErrDenied) || errors.Is(e, auth.ErrNotFound) {
		return app.ErrDenied
	}
	return e
}
func (s *Security) RequireWithin(sc transaction.Scope, a app.ActorRef, resources []string) error {
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
	ids := []string{}
	for id := range seen {
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += 100 {
		end := min(start+100, len(ids))
		if e := s.Access.RequireWithin(sc, s.Actor, identity.Edit, ids[start:end]); e != nil {
			return queryError(e)
		}
	}
	return nil
}

type Graph struct{ Ingress *ingress.Service }

func (g Graph) GuardWithin(sc transaction.Scope) error {
	if g.Ingress == nil {
		return ErrDenied
	}
	return g.Ingress.GuardReferencesWithin(sc)
}
