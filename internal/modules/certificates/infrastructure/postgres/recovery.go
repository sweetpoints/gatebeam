package postgres

import (
	"context"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type Recovery struct{}

func (Recovery) QuarantineRecovery(sc transaction.Scope) error {
	if err := New().WriteLock(sc); err != nil {
		return err
	}
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE certificates_resources SET enabled=false;UPDATE certificates_watermark SET generation=generation+1;DELETE FROM certificates_challenges;DELETE FROM certificates_http_targets;DELETE FROM certificates_http_challenges;DELETE FROM certificates_node_envelopes;UPDATE certificates_attempts SET token='',lease_until='-infinity';UPDATE certificates_preparations SET token='',lease_until='-infinity';UPDATE certificates_issuance_leases SET token='',lease_until='-infinity'`)
		return e
	})
}
