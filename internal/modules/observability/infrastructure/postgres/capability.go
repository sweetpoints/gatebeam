package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CapabilityObject(sc transaction.Scope, archive bool) (out domain.Object, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var raw []byte
		var e error
		if archive {
			e = tx.QueryRow(ctx, `SELECT metadata FROM observability_archive_objects WHERE node_id=$1 AND bytes<=1048576 ORDER BY manifest_sequence DESC LIMIT 1`, s.nodeID).Scan(&raw)
		} else {
			e = tx.QueryRow(ctx, `SELECT o.value FROM observability_batches b CROSS JOIN LATERAL jsonb_array_elements(b.objects) o(value) WHERE b.node_id=$1 AND NOT b.local_cleaned AND (o.value->>'Bytes')::bigint<=1048576 ORDER BY b.committed_at DESC LIMIT 1`, s.nodeID).Scan(&raw)
		}
		if e != nil {
			return e
		}
		if json.Unmarshal(raw, &out) != nil || !domain.ValidObject(out) || out.NodeID != s.nodeID {
			return domain.ErrInvalid
		}
		return nil
	})
	return
}
