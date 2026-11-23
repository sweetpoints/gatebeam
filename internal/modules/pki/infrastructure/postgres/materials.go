package postgres

import (
	"context"
	"gatebeam/internal/modules/pki/application/status"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

// Status fence is taken after identity/ingress/material and before deployment.
// Revocation takes it after principal/account. PKI never takes material or ingress
// locks, so there is no reverse dependency. Every final receipt rechecks it.
func leafFence(sc transaction.Scope, exclusive bool) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		query := `SELECT pg_advisory_xact_lock_shared(hashtextextended('gatebeam/pki/leaf-status',0))`
		if exclusive {
			query = `SELECT pg_advisory_xact_lock(hashtextextended('gatebeam/pki/leaf-status',0))`
		}
		_, err := tx.Exec(ctx, query)
		return err
	})
}
func (*Store) ReadLeafWithin(sc transaction.Scope, leaf status.LeafIdentity) (out status.LeafState, err error) {
	if err := leafFence(sc, false); err != nil {
		return out, err
	}
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
   EXISTS(SELECT 1 FROM pki_leaf_status WHERE issuer_key_fingerprint IS NULL),
   EXISTS(SELECT 1 FROM pki_leaf_status WHERE issuer_key_fingerprint=$1),
   EXISTS(SELECT 1 FROM pki_leaf_status WHERE issuer_key_fingerprint=$1 AND serial=$2 AND leaf_fingerprint=$3 AND state='good'),
   EXISTS(SELECT 1 FROM pki_leaf_status WHERE issuer_key_fingerprint=$1 AND (state='quarantined' OR (serial=$2 AND state='revoked')))`, leaf.IssuerKey, leaf.Serial, leaf.DERDigest).Scan(&out.Unclassified, &out.KnownIssuer, &out.Good, &out.Unsafe)
	})
	return out, err
}
