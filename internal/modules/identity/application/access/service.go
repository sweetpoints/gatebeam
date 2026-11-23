package access

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"time"
)

var ErrDenied = domain.ErrDenied
var ErrInvalid = errors.New("invalid access request")

type Service struct {
	tx          transaction.Runner
	repo        Repository
	audit       Audit
	credentials Credentials
	catalog     Catalog
	now         func() time.Time
}

func New(tx transaction.Runner, r Repository, a Audit, c Credentials, cat Catalog, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if cat == nil {
		cat = DenyCatalog{}
	}
	return &Service{tx, r, a, c, cat, now}
}
func (s *Service) Require(ctx context.Context, actor app.Actor, action app.Action, sites []string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return s.RequireWithin(sc, actor, action, sites) })
}
func (s *Service) current(sc transaction.Scope, actor app.Actor) (domain.Account, *domain.APIToken, error) {
	if actor.UserID == "" || actor.CredentialID == "" || actor.AuthVersion < 1 {
		return domain.Account{}, nil, ErrDenied
	}
	a, e := s.repo.CurrentAccount(sc, actor.UserID)
	if e != nil {
		return a, nil, e
	}
	if a.CanManage() != nil || a.AuthVersion != actor.AuthVersion {
		return a, nil, ErrDenied
	}
	switch actor.CredentialKind {
	case app.SessionCredential:
		v, e := s.repo.SessionByID(sc, actor.CredentialID)
		if e != nil {
			return a, nil, e
		}
		if v.AccountID != a.ID || v.Validate(a, s.now()) != nil {
			return a, nil, ErrDenied
		}
		return a, nil, nil
	case app.TokenCredential:
		t, e := s.repo.TokenByID(sc, actor.CredentialID)
		if e != nil {
			return a, nil, e
		}
		if t.Validate(a, s.now()) != nil {
			return a, nil, ErrDenied
		}
		return a, &t, nil
	}
	return a, nil, ErrDenied
}

// RequireWithin takes the identity shared watermark before reading any identity
// state. Security mutations take the exclusive watermark, never a lock upgrade.
func (s *Service) RequireWithin(sc transaction.Scope, actor app.Actor, action app.Action, sites []string) error {
	if e := s.repo.ReadLock(sc); e != nil {
		return e
	}
	return s.requireLocked(sc, actor, action, sites)
}
func (s *Service) requireLocked(sc transaction.Scope, actor app.Actor, action app.Action, sites []string) error {
	a, t, e := s.current(sc, actor)
	if e != nil {
		return e
	}
	if !a.Role.Allows(action) {
		return ErrDenied
	}
	if action == app.Manage {
		if len(sites) != 0 || t != nil {
			return ErrDenied
		}
		return nil
	}
	if len(sites) == 0 || len(sites) > 100 {
		return ErrDenied
	}
	if t != nil && !t.Allows(action, sites) {
		return ErrDenied
	}
	grants, e := s.repo.Grants(sc, a.ID)
	if e != nil {
		return e
	}
	for _, id := range sites {
		if !domain.ValidResourceID(id) {
			return ErrInvalid
		}
		groups, e := s.catalog.SiteGroupsWithin(sc, id)
		if e != nil {
			return e
		}
		if !domain.Granted(a.Role, grants, id, groups) {
			return ErrDenied
		}
	}
	return nil
}
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (app.Actor, error) {
	var actor app.Actor
	if len(raw) != 43 {
		return actor, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.repo.ReadLock(sc); e != nil {
			return e
		}
		t, e := s.repo.TokenByDigest(sc, s.credentials.Digest(raw))
		if e != nil {
			return e
		}
		a, e := s.repo.CurrentAccount(sc, t.AccountID)
		if e != nil {
			return e
		}
		if t.Validate(a, s.now()) != nil {
			return ErrDenied
		}
		actor = app.Actor{UserID: a.ID, Role: a.Role, AuthVersion: a.AuthVersion, CredentialKind: app.TokenCredential, CredentialID: t.ID}
		return nil
	})
	if e != nil {
		return app.Actor{}, e
	}
	return actor, nil
}
func (s *Service) EventWithin(sc transaction.Scope, actor app.Actor, action, id string) error {
	eid, e := s.credentials.NewID()
	if e != nil {
		return e
	}
	payload, e := json.Marshal(struct {
		ResourceID string `json:"resource_id"`
	}{id})
	if e != nil {
		return e
	}
	return s.audit.Append(sc, audit.Event{ID: eid, ActorID: actor.UserID, Action: action, Payload: payload})
}

// ManageWithin is called only by identity's sensitive-operation transaction,
// which already acquired the exclusive identity watermark before TOTP consumption.
func (s *Service) ManageWithin(sc transaction.Scope, actor app.Actor) error {
	return s.requireLocked(sc, actor, app.Manage, nil)
}
func (s *Service) SetAuthorityWithin(sc transaction.Scope, actor app.Actor, id string, role app.Role, grants []domain.Grant) error {
	if grants == nil {
		return ErrInvalid
	}
	if e := s.ManageWithin(sc, actor); e != nil {
		return e
	}
	if !role.Valid() {
		return ErrInvalid
	}
	if _, e := s.repo.CurrentAccount(sc, id); e != nil {
		return e
	}
	for _, g := range grants {
		if (g.Kind != "site" && g.Kind != "group") || !domain.ValidResourceID(g.ResourceID) {
			return ErrInvalid
		}
	}
	if e := s.repo.ChangeRole(sc, id, role); e != nil {
		return e
	}
	if e := s.repo.ReplaceGrants(sc, id, grants); e != nil {
		return e
	}
	return s.EventWithin(sc, actor, "identity.authority.changed", id)
}
func (s *Service) IssueTokenWithin(sc transaction.Scope, actor app.Actor, actions []string, sites []string, expires time.Time) (TokenView, string, error) {
	// Issuance is restricted to interactive credentials; a token never mints another.
	if actor.CredentialKind != app.SessionCredential || len(actions) == 0 || len(actions) > 3 || len(sites) == 0 || len(sites) > 100 || !expires.After(s.now()) || expires.After(s.now().Add(365*24*time.Hour)) {
		return TokenView{}, "", ErrInvalid
	}
	for _, a := range actions {
		if a != "view" && a != "edit" && a != "publish" {
			return TokenView{}, "", ErrInvalid
		}
		if e := s.requireLocked(sc, actor, app.Action(a), sites); e != nil {
			return TokenView{}, "", e
		}
	}
	a, _, e := s.current(sc, actor)
	if e != nil {
		return TokenView{}, "", e
	}
	id, e := s.credentials.NewID()
	if e != nil {
		return TokenView{}, "", e
	}
	raw, e := s.credentials.Random()
	if e != nil {
		return TokenView{}, "", e
	}
	t := domain.APIToken{ID: id, AccountID: a.ID, Digest: s.credentials.Digest(raw), AuthVersion: a.AuthVersion, Actions: actions, SiteIDs: sites, Expires: expires}
	if e = s.repo.CreateToken(sc, t); e != nil {
		return TokenView{}, "", e
	}
	if e = s.EventWithin(sc, actor, "identity.token.created", id); e != nil {
		return TokenView{}, "", e
	}
	return TokenView{id, a.ID, actions, sites, expires, false}, raw, nil
}
func (s *Service) RevokeTokenWithin(sc transaction.Scope, actor app.Actor, id string) error {
	a, t, e := s.current(sc, actor)
	if e != nil {
		return e
	}
	if t != nil {
		return ErrDenied
	}
	target, e := s.repo.TokenByID(sc, id)
	if e != nil {
		return e
	}
	if target.AccountID != a.ID && a.Role != domain.Admin {
		return ErrDenied
	}
	if e = s.repo.RevokeToken(sc, id); e != nil {
		return e
	}
	return s.EventWithin(sc, actor, "identity.token.revoked", id)
}
func validPage(limit, offset int32) bool {
	return limit > 0 && limit <= 100 && offset >= 0 && offset <= 100000
}
func (s *Service) Accounts(ctx context.Context, a app.Actor, limit, offset int32) ([]AccountView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []AccountView
	if !validPage(limit, offset) {
		return nil, ErrInvalid
	}
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.RequireWithin(sc, a, app.Manage, nil); e != nil {
			return e
		}
		var e error
		out, e = s.repo.ListAccounts(sc, limit, offset)
		return e
	})
	return out, e
}
func (s *Service) Audit(ctx context.Context, a app.Actor, limit, offset int32) ([]AuditView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []AuditView
	if !validPage(limit, offset) {
		return nil, ErrInvalid
	}
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.RequireWithin(sc, a, app.Manage, nil); e != nil {
			return e
		}
		var e error
		out, e = s.repo.ListAudit(sc, limit, offset)
		return e
	})
	return out, e
}
func (s *Service) Tokens(ctx context.Context, a app.Actor, limit, offset int32) ([]TokenView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []TokenView
	if !validPage(limit, offset) {
		return nil, ErrInvalid
	}
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.repo.ReadLock(sc); e != nil {
			return e
		}
		if _, t, e := s.current(sc, a); e != nil {
			return e
		} else if t != nil {
			return ErrDenied
		}
		var e error
		out, e = s.repo.ListTokens(sc, a.UserID, limit, offset)
		return e
	})
	return out, e
}

// ValidateInteractiveWithin expects an already exclusively locked identity transaction.
func (s *Service) ValidateInteractiveWithin(sc transaction.Scope, a app.Actor) error {
	if a.CredentialKind != app.SessionCredential {
		return ErrDenied
	}
	_, _, e := s.current(sc, a)
	return e
}

// GuardWithin establishes identity-before-ingress lock order and checks the
// actual current credential only. It does not consult Catalog or authorize any
// resource. Every caller MUST still perform final resource authorization.
func (s *Service) GuardWithin(sc transaction.Scope, actor app.Actor) error {
	if e := s.repo.ReadLock(sc); e != nil {
		return e
	}
	_, _, e := s.current(sc, actor)
	return e
}

// RequireGroupCreateWithin authorizes creation only inside existing groups with
// current edit grants. Tokens have explicit existing-site scope and cannot mint
// new site scope; administrators use an interactive management credential.
func (s *Service) RequireGroupCreateWithin(sc transaction.Scope, actor app.Actor, groups []string) error {
	if e := s.repo.ReadLock(sc); e != nil {
		return e
	}
	a, t, e := s.current(sc, actor)
	if e != nil {
		return e
	}
	if t != nil || !a.Role.Allows(app.Edit) || len(groups) == 0 || len(groups) > 100 {
		return ErrDenied
	}
	cat, ok := s.catalog.(GroupCatalog)
	if !ok {
		return ErrDenied
	}
	grants, e := s.repo.Grants(sc, a.ID)
	if e != nil {
		return e
	}
	for _, id := range groups {
		if !domain.ValidResourceID(id) {
			return ErrInvalid
		}
		if e = cat.GroupExistsWithin(sc, id); e != nil {
			return e
		}
		if !domain.Granted(a.Role, grants, "", []string{id}) {
			return ErrDenied
		}
	}
	return nil
}

// RequireNotificationOwnerWithin is the narrow background capability for a
// persistent notification channel. Only worker composition supplies this port;
// management must still use a current credential and fresh AdministrativeAction.
// Empty sites means system-only, never an all-sites grant.
func (s *Service) RequireNotificationOwnerWithin(sc transaction.Scope, accountID string, sites []string) error {
	if e := s.repo.ReadLock(sc); e != nil {
		return e
	}
	a, e := s.repo.CurrentAccount(sc, accountID)
	if e != nil {
		return e
	}
	if a.CanManage() != nil || a.Role != domain.Admin {
		return ErrDenied
	}
	if len(sites) > 100 {
		return ErrInvalid
	}
	for _, id := range sites {
		if !domain.ValidResourceID(id) {
			return ErrInvalid
		}
		if _, e = s.catalog.SiteGroupsWithin(sc, id); e != nil {
			return e
		}
	}
	return nil
}

// GuardNotificationWithin freezes current account authority before channel rows.
func (s *Service) GuardNotificationWithin(sc transaction.Scope) error { return s.repo.ReadLock(sc) }
