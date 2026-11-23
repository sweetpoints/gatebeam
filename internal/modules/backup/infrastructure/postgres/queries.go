package postgres

import (
	"context"
	"gatebeam/internal/modules/backup/application"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (c Catalog) RecordsWithin(sc transaction.Scope, limit, offset int) (out []application.Record, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id,created_at,bytes,CASE WHEN jsonb_array_length(coalesce(manifest->'Files','[]'))>0 THEN 'recorded' ELSE 'omitted_for_recovery' END FROM backup_runs ORDER BY created_at DESC,id LIMIT $1 OFFSET $2`, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r application.Record
			if e = rows.Scan(&r.ID, &r.Created, &r.Bytes, &r.DetailStatus); e != nil {
				return e
			}
			r.ArtifactVerification = "required"
			out = append(out, r)
		}
		return rows.Err()
	})
	return
}
