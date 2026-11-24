package postgres

import (
	"context"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/modules/pki/infrastructure/postgres/dbgen"
	"gatebeam-ca/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgtype"
)

func (*Store) InsertGrant(sc transaction.Scope, g application.Grant) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		p := g.Principal
		if e := q.InsertPrincipal(c, dbgen.InsertPrincipalParams{ID: p.ID, Names: p.Names, Purpose: string(p.Usage), Directory: p.Directory, Expires: pgtype.Timestamptz{Time: p.Expires, Valid: true}, Disabled: p.Disabled}); e != nil {
			return e
		}
		return q.InsertGrant(c, dbgen.InsertGrantParams{ID: g.ID, PrincipalID: p.ID})
	})
}
func (*Store) GrantPrincipal(sc transaction.Scope, id string) (string, error) {
	var out string
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		out, e = q.GrantPrincipal(c, id)
		return e
	})
	return out, e
}
func (*Store) ReplaceBinding(sc transaction.Scope, grant string, b domain.Binding) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		if e := q.ExpireBindings(c, grant); e != nil {
			return e
		}
		return q.InsertBinding(c, dbgen.InsertBindingParams{ID: b.ID, GrantID: grant, Cipher: b.Cipher, Expires: pgtype.Timestamptz{Time: b.Expires, Valid: true}})
	})
}
func (*Store) DisablePrincipal(sc transaction.Scope, id string) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { return q.DisablePrincipal(c, id) })
}
