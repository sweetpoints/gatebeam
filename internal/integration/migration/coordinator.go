// Package migration authorizes read-only entry checks with the caller's current
// credential scope, both before network I/O and immediately before returning.
package migration

import (
	"context"
	"errors"
	"gatebeam/internal/modules/deployment/application/preflight"
	"gatebeam/internal/modules/deployment/domain"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
)

var ErrDenied = errors.New("migration check denied")

func denial(e error) error {
	if errors.Is(e, access.ErrDenied) {
		return ErrDenied
	}
	return e
}

type ActorRef struct {
	UserID                       string
	AuthVersion                  int64
	CredentialKind, CredentialID string
}
type Checker interface {
	Check(context.Context, string, preflight.EntryAddress) (preflight.Report, error)
}
type Coordinator struct {
	access *access.Service
	check  Checker
}

func New(a *access.Service, c Checker) *Coordinator { return &Coordinator{a, c} }
func (c *Coordinator) Check(ctx context.Context, a ActorRef, siteID string, entry preflight.EntryAddress) (preflight.Report, error) {
	actor := identity.Actor{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: identity.CredentialKind(a.CredentialKind), CredentialID: a.CredentialID}
	if e := c.access.Require(ctx, actor, identity.View, []string{siteID}); e != nil {
		return preflight.Report{}, denial(e)
	}
	out, e := c.check.Check(ctx, siteID, entry)
	if e != nil {
		return out, e
	}
	if e = c.access.Require(ctx, actor, identity.View, []string{siteID}); e != nil {
		return preflight.Report{}, denial(e)
	}
	if out.Revision < 1 {
		return preflight.Report{}, domain.ErrConflict
	}
	return out, nil
}
