package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ListWithin(sc transaction.Scope, a query.ActorRef, limit, offset int) (out []query.Input, err error) {
	raw, _ := json.Marshal(a)
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id::text,state,actor,filter,objects,watermark,scan_bytes,expires_at,error,'[]'::jsonb,coalesce(lease::text,''),coverage,truncated FROM observability_queries WHERE actor=$1 AND expires_at>clock_timestamp() ORDER BY created_at DESC,id LIMIT $2 OFFSET $3`, raw, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			in, _, e := scanInput(rows)
			if e != nil {
				return e
			}
			in.Objects = nil
			out = append(out, in)
		}
		return rows.Err()
	})
	return
}
func (s *Store) CancelWithin(sc transaction.Scope, id string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE observability_queries SET state='cancelled',result='[]',error='',lease=NULL,lease_until=NULL WHERE id=$1 AND state IN ('queued','running','coordinating')`, id)
		return e
	})
}

// CleanupWithin serializes local snapshot admission with unlink. An active
// local query pins its immutable object until completion/cancellation/expiry.
func (s *Store) CleanupWithin(sc transaction.Scope, b domain.Batch, effect func() error) error {
	applied := false
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('observability_manifest_lifecycle',0))`); e != nil {
			return e
		}
		var busy bool
		keys := []string{}
		for _, o := range b.Objects {
			keys = append(keys, o.Key)
		}
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observability_queries q,jsonb_array_elements(q.objects) obj WHERE q.filter->>'source'='local' AND q.state IN ('queued','running','coordinating') AND q.expires_at>clock_timestamp() AND obj->>'Key'=ANY($1))`, keys).Scan(&busy); e != nil {
			return e
		}
		if busy {
			return domain.ErrQueryBusy
		}
		if e := effect(); e != nil {
			return e
		}
		v, e := tx.Exec(ctx, `UPDATE observability_batches SET local_cleaned=true WHERE id=$1 AND NOT local_cleaned AND EXISTS(SELECT 1 FROM observability_manifests WHERE batch_id=$1 AND state='committed')`, b.ID)
		if e == nil {
			applied = v.RowsAffected() == 1
		}
		return e
	})
	if err != nil || !applied {
		return err
	}
	return alertOutcome(sc, "ArchivePipelineChanged", "local-log-volume", "pipeline", "resolved", 0)
}
