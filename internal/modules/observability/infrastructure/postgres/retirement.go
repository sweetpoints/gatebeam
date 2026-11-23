package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BeginRetirement persists the proof before filesystem cleanup. CursorWithin
// refuses further ingest into a retiring identity, including after a crash.
func (s *Store) BeginRetirement(sc transaction.Scope, seg domain.Segment) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if sourceNode(seg.NodeID) != s.nodeID || !seg.Closed || seg.Path == "access.log" {
			return domain.ErrInvalid
		}
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "source/"+seg.ID); e != nil {
			return e
		}
		if seg.Size == 0 && seg.Fingerprint == "" {
			logical := fmt.Sprintf("%x", sha256.Sum256([]byte(uuid.NewString())))
			if _, e := tx.Exec(ctx, `INSERT INTO observability_segments(id,physical_id,fingerprint,source_name,node_id) SELECT $1,$2,'',$3,$4 WHERE NOT EXISTS(SELECT 1 FROM observability_segments WHERE physical_id=$2 AND NOT retired) ON CONFLICT DO NOTHING`, logical, seg.ID, seg.Path, s.nodeID); e != nil {
				return e
			}
		}
		tag, e := tx.Exec(ctx, `UPDATE observability_segments s SET retirement_size=$4,source_name=$2 WHERE physical_id=$1 AND fingerprint=$3 AND NOT retired AND source_offset=$4 AND NOT EXISTS(SELECT 1 FROM observability_batches b WHERE b.segment_id=s.id AND NOT EXISTS(SELECT 1 FROM observability_manifests m WHERE m.batch_id=b.id AND m.state='committed'))`, seg.ID, seg.Path, seg.Fingerprint, seg.Size)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return domain.ErrIncomplete
		}
		return nil
	})
}

type Retirement struct {
	ID      string
	Segment domain.Segment
}

func (s *Store) Retirements(sc transaction.Scope) (out []Retirement, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id,physical_id,source_name,fingerprint,retirement_size,node_id FROM observability_segments WHERE retirement_size IS NOT NULL AND NOT retired AND node_id=$1 ORDER BY updated_at LIMIT 16`, s.nodeID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r Retirement
			r.Segment.Closed = true
			if e = rows.Scan(&r.ID, &r.Segment.ID, &r.Segment.Path, &r.Segment.Fingerprint, &r.Segment.Size, &r.Segment.NodeID); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return
}
func (s *Store) FinishRetirement(sc transaction.Scope, id string) error {
	applied := false
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		result, e := tx.Exec(ctx, `UPDATE observability_segments SET retired=true WHERE id=$1 AND retirement_size IS NOT NULL AND NOT retired AND node_id=$2`, id, s.nodeID)
		if e != nil {
			return e
		}
		applied = result.RowsAffected() == 1
		return nil
	})
	if err != nil || !applied {
		return err
	}
	return alertOutcome(sc, "ArchivePipelineChanged", "local-log-volume", "pipeline", "resolved", 0)
}
