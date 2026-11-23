package notificationaccess

import (
	"context"
	"errors"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/application/auth"
	ingress "gatebeam/internal/modules/ingress/application"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/platform/transaction"
)

type Security struct {
	Authentication *auth.Service
	Access         *access.Service
	Ingress        *ingress.Service
	Actor          identity.Actor
	Code           string
	Background     bool
}

func (s *Security) Within(ctx context.Context, a app.ActorRef, fn func(transaction.Scope) error) error {
	if s.Background || s.Authentication == nil || a.UserID != s.Actor.UserID || a.CredentialID != s.Actor.CredentialID || a.CredentialKind != string(s.Actor.CredentialKind) || a.AuthVersion != s.Actor.AuthVersion {
		return app.ErrDenied
	}
	e := s.Authentication.AdministrativeAction(ctx, s.Actor, s.Code, fn)
	if errors.Is(e, auth.ErrDenied) || errors.Is(e, auth.ErrNotFound) {
		return app.ErrDenied
	}
	return e
}
func (s *Security) GuardWithin(sc transaction.Scope) error {
	if s.Access == nil {
		return app.ErrDenied
	}
	if s.Background {
		if e := s.Access.GuardNotificationWithin(sc); e != nil {
			return e
		}
		return s.Ingress.GuardReferencesWithin(sc)
	}
	if e := s.Access.GuardWithin(sc, s.Actor); e != nil {
		return e
	}
	return s.Ingress.GuardReferencesWithin(sc)
}
func (s *Security) ReadWithin(sc transaction.Scope, a app.ActorRef) error {
	if s.Background || a.UserID != s.Actor.UserID || a.CredentialID != s.Actor.CredentialID || a.AuthVersion != s.Actor.AuthVersion || a.CredentialKind != string(s.Actor.CredentialKind) {
		return app.ErrDenied
	}
	if e := s.Access.RequireWithin(sc, s.Actor, identity.Manage, nil); e != nil {
		return app.ErrDenied
	}
	return nil
}
func (s *Security) DeliveryWithin(sc transaction.Scope, c app.Channel, e app.Event) error {
	if s.Access == nil || s.Ingress == nil {
		return app.ErrDenied
	}
	if s.Background {
		if err := s.Access.RequireNotificationOwnerWithin(sc, c.OwnerID, c.SiteIDs); err != nil {
			if errors.Is(err, access.ErrDenied) || errors.Is(err, auth.ErrNotFound) {
				return app.ErrDenied
			}
			return err
		}
	} else {
		// API management retains the entire current interactive credential. The
		// account-only persistent authority port is reserved for worker assembly.
		if err := s.Access.RequireWithin(sc, s.Actor, identity.Manage, nil); err != nil {
			return app.ErrDenied
		}
		if len(c.SiteIDs) > 0 {
			if err := s.Access.RequireWithin(sc, s.Actor, identity.View, c.SiteIDs); err != nil {
				return app.ErrDenied
			}
		}
	}
	if c.System {
		if e.Kind == "target_health" || e.Kind == "target_dns" || e.Kind == "certificate_renewal" || e.Kind == "certificate_expiry" {
			return app.ErrDenied
		}
		return nil
	}
	if e.Kind == "channel_test" {
		return nil
	}
	if e.Kind != "target_health" && e.Kind != "target_dns" && e.Kind != "certificate_renewal" && e.Kind != "certificate_expiry" {
		return app.ErrDenied
	}
	sites, err := s.Ingress.AffectedSitesWithin(sc, e.ResourceID)
	if err != nil {
		if errors.Is(err, ingress.ErrNotFound) || errors.Is(err, ingress.ErrDenied) {
			return app.ErrDenied
		}
		return err
	}
	if len(sites) == 0 {
		return app.ErrDenied
	}
	allowed := map[string]bool{}
	for _, id := range c.SiteIDs {
		allowed[id] = true
	}
	for _, id := range sites {
		if !allowed[id] {
			return app.ErrDenied
		}
	}
	return nil
}
