package postgres

import (
	"context"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/modules/certificates/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
)

func (*Store) PreparationDue(sc transaction.Scope) (out []app.Resource, err error) {
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		rows, e := q.CertificatePreparationDue(ctx)
		for _, r := range rows {
			out = append(out, app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body})
		}
		return e
	})
	return
}
func (*Store) ClaimPreparation(sc transaction.Scope, r app.Resource, token string, until time.Time) (out domain.Attempt, err error) {
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		if e := q.CertificatePreparationCreate(ctx, dbgen.CertificatePreparationCreateParams{Kind: r.Kind, ID: id(r.ID), Revision: r.Revision}); e != nil {
			return e
		}
		failures, e := q.CertificatePreparationClaim(ctx, dbgen.CertificatePreparationClaimParams{Kind: r.Kind, ID: id(r.ID), Revision: r.Revision, Token: token, LeaseUntil: pgtype.Timestamptz{Time: until, Valid: true}})
		out.Failures = int(failures)
		return e
	})
	return
}
func (*Store) FinishPreparation(sc transaction.Scope, r app.Resource, token string, result domain.Attempt) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		n, e := q.CertificatePreparationFinish(ctx, dbgen.CertificatePreparationFinishParams{Kind: r.Kind, ID: id(r.ID), Revision: r.Revision, Token: token, Failures: int32(result.Failures), NextAttempt: pgtype.Timestamptz{Time: result.NextAttempt, Valid: true}})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		return nil
	})
}
