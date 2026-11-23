package postgres

import (
	"context"
	app "gatebeam/internal/modules/pki/application"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/modules/pki/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
)

func (*Store) Enrollments(sc transaction.Scope) (out []app.EnrollmentView, err error) {
	out = []app.EnrollmentView{}
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		rows, e := q.EnrollmentMetadata(ctx)
		for _, r := range rows {
			v := app.EnrollmentView{Grant: app.Grant{ID: r.GrantID, Principal: domain.Principal{ID: r.PrincipalID, Names: r.Names, Usage: domain.Usage(r.Purpose), Directory: r.Directory, Expires: r.Expires.Time, Disabled: r.Disabled}}, BindingState: r.BindingState}
			if r.BindingExpires.Valid {
				t := r.BindingExpires.Time
				v.BindingExpires = &t
			}
			out = append(out, v)
		}
		return e
	})
	return
}
func (*Store) IssuedMetadata(sc transaction.Scope) (out []app.IssuedView, err error) {
	out = []app.IssuedView{}
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		rows, e := q.IssuedMetadata(ctx)
		for _, r := range rows {
			v := app.IssuedView{Issuer: r.IssuerID, Serial: r.Serial, PrincipalID: r.PrincipalID, Names: r.Names, Purpose: r.Purpose, NotBefore: r.NotBefore.Time, NotAfter: r.NotAfter.Time}
			if r.RevokedAt.Valid {
				t := r.RevokedAt.Time
				v.RevokedAt = &t
			}
			if r.Reason.Valid {
				n := int(r.Reason.Int32)
				v.Reason = &n
			}
			out = append(out, v)
		}
		return e
	})
	return
}
