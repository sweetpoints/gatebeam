package postgres

import (
	"context"
	"encoding/json"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgtype"
)

func (r *Runtime) SaveRouteVerification(ctx context.Context, report edge.RouteVerification) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return r.tx.Within(ctx, func(sc transaction.Scope) error {
		return use(sc, func(c context.Context, q *dbgen.Queries) error {
			return q.SaveRouteVerification(c, dbgen.SaveRouteVerificationParams{ArtifactID: report.ArtifactID, Version: report.Version, Generation: report.Generation, CheckedAt: pgtype.Timestamptz{Time: report.CheckedAt, Valid: true}, Body: body})
		})
	})
}

// CurrentRouteVerification is an owning read contract for operational views.
// Stale/failed artifact evidence can never replace the active artifact's result.
func (r *Runtime) CurrentRouteVerification(ctx context.Context) (out edge.RouteVerification, err error) {
	err = r.tx.Within(ctx, func(sc transaction.Scope) error {
		return use(sc, func(c context.Context, q *dbgen.Queries) error {
			b, e := q.CurrentRouteVerification(c)
			if e != nil {
				return e
			}
			return json.Unmarshal(b, &out)
		})
	})
	return
}
