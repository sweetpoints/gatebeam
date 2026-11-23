package postgres

import (
	"context"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/modules/backup/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

// RecoveryReceiptsWithin reads backup-owned metadata using exactly the caller's
// snapshot. It cannot fall back to Catalog.DB or import another owner's state.
func (c Catalog) RecoveryReceiptsWithin(sc transaction.Scope) ([]application.RecoveryReceipt, error) {
	out := make([]application.RecoveryReceipt, 0)
	e := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id,created_at,cipher_sha256,bytes,(manifest->>'Version')::integer,manifest->>'ID',(manifest->>'Created')::timestamptz,manifest->>'Snapshot',manifest->>'Epoch',manifest->>'Schema',COALESCE(manifest->>'Recipient','') FROM backup_runs ORDER BY created_at,id LIMIT $1`, domain.MaxRows+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r application.RecoveryReceipt
			p := &r.Manifest
			if e = rows.Scan(&r.ID, &r.Created, &r.CipherSHA256, &r.Bytes, &p.Version, &p.ID, &p.Created, &p.Snapshot, &p.Epoch, &p.Schema, &p.Recipient); e != nil {
				return e
			}
			out = append(out, r)
			if len(out) > domain.MaxRows {
				return domain.ErrInvalid
			}
		}
		return rows.Err()
	})
	return out, e
}
