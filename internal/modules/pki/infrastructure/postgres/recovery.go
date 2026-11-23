package postgres

import (
	"context"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (*Store) QuarantineRecovery(sc transaction.Scope) error {
	if err := leafFence(sc, true); err != nil {
		return err
	}
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE pki_principals SET disabled=true;UPDATE pki_eab SET consumed=true;UPDATE pki_accounts SET status='deactivated',revision=revision+1;UPDATE pki_orders SET status='invalid',revision=revision+1 WHERE status IN('pending','ready');DELETE FROM pki_nonces;INSERT INTO pki_revocations(issuer_id,serial,reason,revoked_at) SELECT issuer_id,serial,1,clock_timestamp() FROM pki_certificates ON CONFLICT DO NOTHING;INSERT INTO pki_restore_quarantine SELECT id,'unproved_security_watermark' FROM pki_issuers ON CONFLICT DO NOTHING`)
		return e
	})
}
