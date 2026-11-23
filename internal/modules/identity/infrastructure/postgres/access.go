package postgres

import (
	"context"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/modules/identity/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
)

func (r *Repository) ReadLock(sc transaction.Scope) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { return q.ReadIdentityWatermark(c) })
}
func (r *Repository) CurrentAccount(sc transaction.Scope, id string) (domain.Account, error) {
	var out domain.Account
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.CurrentAccount(c, id)
		out = account(v)
		return e
	})
	return out, e
}
func (r *Repository) SessionByID(sc transaction.Scope, id string) (domain.Session, error) {
	var out domain.Session
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.SessionByID(c, id)
		out = domain.Session{ID: v.ID, AccountID: v.AccountID, TokenHash: v.TokenHash, CSRFHash: v.CsrfHash, AuthVersion: v.AuthVersion, Expires: v.Expires.Time, Revoked: v.Revoked}
		return e
	})
	return out, e
}
func token(v dbgen.IdentityToken) domain.APIToken {
	return domain.APIToken{ID: v.ID, AccountID: v.AccountID, Digest: v.Digest, AuthVersion: v.AuthVersion, Actions: v.Actions, SiteIDs: v.SiteIds, Expires: v.Expires.Time, Revoked: v.Revoked}
}
func (r *Repository) TokenByID(sc transaction.Scope, id string) (domain.APIToken, error) {
	var out domain.APIToken
	e := use(sc, func(c context.Context, q *dbgen.Queries) error { v, e := q.TokenByID(c, id); out = token(v); return e })
	return out, e
}
func (r *Repository) TokenByDigest(sc transaction.Scope, id string) (domain.APIToken, error) {
	var out domain.APIToken
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.TokenByDigest(c, id)
		out = token(v)
		return e
	})
	return out, e
}
func (r *Repository) CreateToken(sc transaction.Scope, t domain.APIToken) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.CreateToken(c, dbgen.CreateTokenParams{ID: t.ID, AccountID: t.AccountID, Digest: t.Digest, AuthVersion: t.AuthVersion, Actions: t.Actions, SiteIds: t.SiteIDs, Expires: ts(t.Expires), Revoked: t.Revoked})
	})
}
func (r *Repository) RevokeToken(sc transaction.Scope, id string) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { _, e := q.RevokeToken(c, id); return e })
}
func (r *Repository) Grants(sc transaction.Scope, id string) ([]domain.Grant, error) {
	out := []domain.Grant{}
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.Grants(c, id)
		for _, g := range v {
			out = append(out, domain.Grant{Kind: g.Kind, ResourceID: g.ResourceID})
		}
		return e
	})
	return out, e
}
func (r *Repository) ReplaceGrants(sc transaction.Scope, id string, grants []domain.Grant) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		if e := q.ClearGrants(c, id); e != nil {
			return e
		}
		for _, g := range grants {
			if e := q.AddGrant(c, dbgen.AddGrantParams{AccountID: id, Kind: g.Kind, ResourceID: g.ResourceID}); e != nil {
				return e
			}
		}
		return nil
	})
}
func (r *Repository) ChangeRole(sc transaction.Scope, id string, role domain.Role) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.ChangeRole(c, dbgen.ChangeRoleParams{ID: id, Role: string(role)})
	})
}
func (r *Repository) ListAccounts(sc transaction.Scope, limit, offset int32) ([]access.AccountView, error) {
	out := []access.AccountView{}
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		vs, e := q.ListAccounts(c, dbgen.ListAccountsParams{Limit: limit, Offset: offset})
		for _, v := range vs {
			out = append(out, access.AccountView{ID: v.ID, Name: v.Name, State: v.State, Role: domain.Role(v.Role), AuthVersion: v.AuthVersion})
		}
		return e
	})
	return out, e
}
func (r *Repository) ListTokens(sc transaction.Scope, id string, limit, offset int32) ([]access.TokenView, error) {
	out := []access.TokenView{}
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		vs, e := q.ListTokens(c, dbgen.ListTokensParams{AccountID: id, Limit: limit, Offset: offset})
		for _, v := range vs {
			out = append(out, access.TokenView{ID: v.ID, AccountID: v.AccountID, Actions: v.Actions, SiteIDs: v.SiteIds, Expires: v.Expires.Time, Revoked: v.Revoked})
		}
		return e
	})
	return out, e
}
func (r *Repository) ListAudit(sc transaction.Scope, limit, offset int32) ([]access.AuditView, error) {
	rows, err := audit.NewReader().RecentWithin(sc, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]access.AuditView, 0, len(rows))
	for _, r := range rows {
		out = append(out, access.AuditView{ID: r.ID, ActorID: r.ActorID, Action: r.Action, OccurredAt: r.OccurredAt})
	}
	return out, nil
}
