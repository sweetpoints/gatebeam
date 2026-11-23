package postgres

import (
	"context"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (*Repository) QuarantineRecovery(sc transaction.Scope) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE identity_accounts SET state='disabled',password_hash='',seed='',invite_hash='',invite_expires='-infinity',auth_version=auth_version+1;UPDATE identity_sessions SET revoked=true;UPDATE identity_tokens SET revoked=true;UPDATE identity_recovery SET consumed=true;UPDATE identity_challenges SET consumed=true;DELETE FROM identity_grants;UPDATE identity_restore_bootstrap SET available=true`)
		return e
	})
}
func (*Repository) ConsumeRecoveryBootstrap(sc transaction.Scope) (bool, error) {
	var ready bool
	e := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE identity_restore_bootstrap SET available=false WHERE singleton AND available`)
		ready = tag.RowsAffected() == 1
		return e
	})
	return ready, e
}
