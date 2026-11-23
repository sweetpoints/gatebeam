package postgres

import (
	"context"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (*Store) QuarantineQueriesWithin(sc transaction.Scope) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM observability_queries`)
		return e
	})
}
