package postgres

import (
	"context"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

// VerifyLogCutoff proves persisted cursors and, when configured, committed
// archive receipts through a frozen finite source offset. Fsync is not a receipt.
func (s *Store) VerifyLogCutoff(sc transaction.Scope, segments []domain.Segment, archived bool) (ready bool, err error) {
	if s.nodeID == "" || len(segments) > 2048 {
		return false, domain.ErrInvalid
	}
	ready = true
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		for _, seg := range segments {
			if seg.NodeID != s.nodeID || seg.Size < 0 || seg.ID == "" {
				return domain.ErrInvalid
			}
			if seg.Size == 0 {
				continue
			}
			var complete bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observability_segments s WHERE s.node_id=$1 AND s.physical_id=$2 AND s.fingerprint=$3 AND s.source_offset >= $4 AND (NOT $5::boolean OR NOT EXISTS(SELECT 1 FROM observability_batches b WHERE b.segment_id=s.id AND NOT EXISTS(SELECT 1 FROM observability_manifests m WHERE m.batch_id=b.id AND m.state='committed'))))`, s.nodeID, seg.ID, seg.Fingerprint, seg.Size, archived).Scan(&complete); e != nil {
				return e
			}
			ready = ready && complete
		}
		return nil
	})
	return
}
