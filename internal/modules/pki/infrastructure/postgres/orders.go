package postgres

import (
	"context"
	"encoding/json"
	app "gatebeam/internal/modules/pki/application/acme"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/modules/pki/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgtype"
)

func (*Store) InsertOrder(sc transaction.Scope, o domain.Order) error {
	b, e := json.Marshal(o.Challenges)
	if e != nil {
		return e
	}
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.InsertOrder(c, dbgen.InsertOrderParams{ID: o.ID, AccountID: o.AccountID, Directory: o.Directory, Names: o.Names, Purpose: string(o.Usage), Status: o.Status, Expires: pgtype.Timestamptz{Time: o.Expires, Valid: true}, Challenges: b, Revision: o.Revision})
	})
}
func (*Store) Order(sc transaction.Scope, id, account string) (domain.Order, error) {
	var o domain.Order
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.ReadOrder(c, dbgen.ReadOrderParams{ID: id, AccountID: account})
		if e != nil {
			return e
		}
		o = domain.Order{ID: v.ID, AccountID: v.AccountID, Directory: v.Directory, Names: v.Names, Usage: domain.Usage(v.Purpose), Status: v.Status, Expires: v.Expires.Time, Revision: v.Revision}
		return json.Unmarshal(v.Challenges, &o.Challenges)
	})
	return o, e
}
func (*Store) SaveOrder(sc transaction.Scope, o domain.Order, revision int64) error {
	b, e := json.Marshal(o.Challenges)
	if e != nil {
		return e
	}
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.SaveOrder(c, dbgen.SaveOrderParams{ID: o.ID, Status: o.Status, Challenges: b, Revision: revision})
		if e == nil && n != 1 {
			return app.ErrDenied
		}
		return e
	})
}
func (*Store) Orders(sc transaction.Scope, account, after string) ([]string, error) {
	var out []string
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		out, e = q.ListOrders(c, dbgen.ListOrdersParams{AccountID: account, ID: after})
		return e
	})
	return out, e
}
func (*Store) InsertCertificate(sc transaction.Scope, v domain.IssuedCertificate) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.InsertCertificate(c, dbgen.InsertCertificateParams{OrderID: v.OrderID, IssuerID: string(v.IssuerID), Serial: string(v.Serial), Der: v.DER, Chain: v.Chain, NotBefore: pgtype.Timestamptz{Time: v.NotBefore, Valid: true}, NotAfter: pgtype.Timestamptz{Time: v.NotAfter, Valid: true}})
	})
}
func (*Store) Certificate(sc transaction.Scope, id string) (domain.IssuedCertificate, error) {
	var out domain.IssuedCertificate
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.ReadCertificate(c, id)
		out = domain.IssuedCertificate{OrderID: v.OrderID, IssuerID: domain.IssuerID(v.IssuerID), Serial: domain.Serial(v.Serial), DER: v.Der, Chain: v.Chain, NotBefore: v.NotBefore.Time, NotAfter: v.NotAfter.Time}
		return e
	})
	return out, e
}
