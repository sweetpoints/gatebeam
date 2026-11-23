package postgres

import (
	"context"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type Recovery struct{}

func (Recovery) QuarantineRecovery(sc transaction.Scope) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE notification_channels SET enabled=false;UPDATE notification_deliveries SET status='disabled',lease_token=NULL,deadline=NULL`)
		return e
	})
}
