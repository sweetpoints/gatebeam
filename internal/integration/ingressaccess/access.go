// Package ingressaccess maps consumer-owned ports without crossing domain/SQL boundaries.
package ingressaccess

import (
	"errors"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	ingress "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/platform/transaction"
)

type Catalog struct{ Ingress *ingress.Service }

func (c *Catalog) SiteGroupsWithin(sc transaction.Scope, id string) ([]string, error) {
	if c == nil || c.Ingress == nil {
		return nil, access.ErrDenied
	}
	v, e := c.Ingress.SiteGroupsWithin(sc, id)
	if e != nil {
		if errors.Is(e, ingress.ErrNotFound) {
			return nil, access.ErrDenied
		}
		return nil, e
	}
	return v, nil
}
func (c *Catalog) GroupExistsWithin(sc transaction.Scope, id string) error {
	if c == nil || c.Ingress == nil {
		return access.ErrDenied
	}
	if e := c.Ingress.GroupExistsWithin(sc, id); e != nil {
		if errors.Is(e, ingress.ErrNotFound) {
			return access.ErrDenied
		}
		return e
	}
	return nil
}

type Authorizer struct{ Identity *access.Service }

func actor(a ingress.ActorRef) identity.Actor {
	return identity.Actor{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: identity.CredentialKind(a.CredentialKind), CredentialID: a.CredentialID}
}
func denial(e error) error {
	if errors.Is(e, access.ErrDenied) {
		return ingress.ErrDenied
	}
	return e
}
func (a Authorizer) GuardWithin(sc transaction.Scope, v ingress.ActorRef) error {
	return denial(a.Identity.GuardWithin(sc, actor(v)))
}
func (a Authorizer) RequireWithin(sc transaction.Scope, v ingress.ActorRef, action string, ids []string) error {
	return denial(a.Identity.RequireWithin(sc, actor(v), identity.Action(action), ids))
}
func (a Authorizer) RequireGroupCreateWithin(sc transaction.Scope, v ingress.ActorRef, groups []string) error {
	return denial(a.Identity.RequireGroupCreateWithin(sc, actor(v), groups))
}
