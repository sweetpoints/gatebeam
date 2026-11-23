package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgtype"
)

func (*Store) PublishSite(sc transaction.Scope, v application.VerifiedSite, domains []string) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		b, e := json.Marshal(v.Config)
		if e != nil {
			return e
		}
		if e = changed(q.PublishSite(ctx, dbgen.PublishSiteParams{ID: id(v.ID), Revision: pgtype.Int8{Int64: v.Revision, Valid: true}, Config: b})); e != nil {
			return e
		}
		if e = q.ClearDomains(ctx, id(v.ID)); e != nil {
			return e
		}
		for _, d := range domains {
			if e = q.ClaimDomain(ctx, dbgen.ClaimDomainParams{ID: id(v.ID), Domain: d}); e != nil {
				return e
			}
		}
		return nil
	})
}
func (*Store) PublishTarget(sc transaction.Scope, v application.VerifiedTarget) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		b, e := json.Marshal(v.Config)
		if e != nil {
			return e
		}
		return changed(q.PublishTarget(ctx, dbgen.PublishTargetParams{ID: id(v.ID), Revision: pgtype.Int8{Int64: v.Revision, Valid: true}, Config: b}))
	})
}
