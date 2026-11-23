package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/postgres/dbgen"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Store struct {
	nodeID    string
	nodeEpoch uint64
}

func New() *Store                  { return &Store{nodeID: "legacy"} }
func NewNode(nodeID string) *Store { return &Store{nodeID: nodeID} }
func (s *Store) CursorWithin(sc transaction.Scope, seg domain.Segment) (out domain.Cursor, err error) {
	if sourceNode(seg.NodeID) != s.nodeID {
		return out, domain.ErrSourceChanged
	}
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if seg.Fingerprint == "" {
			var offset int64
			e := tx.QueryRow(ctx, `SELECT source_offset FROM observability_segments WHERE physical_id=$1 AND NOT retired FOR UPDATE`, seg.ID).Scan(&offset)
			if errors.Is(e, pgx.ErrNoRows) {
				return domain.ErrIncomplete
			}
			if e != nil {
				return e
			}
			if offset > 0 {
				return domain.ErrSourceChanged
			}
			return domain.ErrIncomplete
		}
		physical := seg.ID
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "source/"+physical); e != nil {
			return e
		}
		var logical string
		var retiring bool
		e := tx.QueryRow(ctx, `SELECT id,retirement_size IS NOT NULL FROM observability_segments WHERE physical_id=$1 AND NOT retired`, physical).Scan(&logical, &retiring)
		if errors.Is(e, pgx.ErrNoRows) {
			var prior bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observability_segments WHERE physical_id=$1)`, physical).Scan(&prior); e != nil {
				return e
			}
			logical = physical
			if prior {
				logical = fmt.Sprintf("%x", sha256.Sum256([]byte(uuid.NewString())))
			}
			if _, e = tx.Exec(ctx, `INSERT INTO observability_segments(id,physical_id,fingerprint,source_name,node_id) VALUES($1,$2,$3,$4,$5)`, logical, physical, seg.Fingerprint, seg.Path, sourceNode(seg.NodeID)); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if retiring {
			return domain.ErrIncomplete
		}
		seg.ID = logical

		v, e := q.LockSegment(ctx, seg.ID)
		if e != nil {
			return e
		}
		if v.NodeID != sourceNode(seg.NodeID) || v.Fingerprint != seg.Fingerprint || v.SourceOffset > seg.Size {
			return domain.ErrSourceChanged
		}
		out = domain.Cursor{SegmentID: seg.ID, Offset: v.SourceOffset, Fingerprint: v.Fingerprint, Dropping: v.Dropping, Anchor: v.Anchor}
		return nil
	})
	return
}
func (s *Store) CommitWithin(sc transaction.Scope, seg domain.Segment, b domain.Batch) error {
	accepted := false
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		v, e := q.LockSegment(ctx, seg.ID)
		if e != nil {
			return e
		}
		if v.NodeID != sourceNode(seg.NodeID) || sourceNode(b.NodeID) != sourceNode(seg.NodeID) || v.Fingerprint != seg.Fingerprint || b.SegmentID != seg.ID {
			return domain.ErrSourceChanged
		}
		checksum, e := q.BatchChecksum(ctx, b.ID)
		if e == nil {
			if checksum != b.SourceChecksum {
				return domain.ErrSourceChanged
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if v.SourceOffset != b.Start || b.End <= b.Start || b.End-b.Start > domain.MaxRead {
			return domain.ErrSourceChanged
		}
		objects, e := json.Marshal(b.Objects)
		if e != nil {
			return e
		}
		if e = q.InsertBatch(ctx, dbgen.InsertBatchParams{ID: b.ID, SegmentID: seg.ID, StartOffset: b.Start, EndOffset: b.End, SourceChecksum: b.SourceChecksum, Objects: objects, InvalidCount: b.Invalid, SchemaCount: b.Schema, OversizeCount: b.Oversize, NodeID: sourceNode(b.NodeID)}); e != nil {
			return e
		}
		for _, v := range b.Buckets {
			if e = q.MergeBucket(ctx, dbgen.MergeBucketParams{Minute: pgtype.Timestamptz{Time: v.Minute, Valid: true}, SiteID: v.SiteID, Route: v.Route, Method: v.Method, StatusClass: int32(v.StatusClass), Requests: v.Count, Micros: v.Micros, Bytes: v.Bytes, Histogram: v.Histogram[:], ConfigID: v.ConfigID}); e != nil {
				return e
			}
		}
		if b.Invalid+b.Schema+b.Oversize > 0 {
			payload, e := json.Marshal(struct{ Start, End, Invalid, Schema, Oversize int64 }{b.Start, b.End, b.Invalid, b.Schema, b.Oversize})
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO outbox(event_id,event_type,schema_version,aggregate_id,aggregate_version,payload) VALUES($1,'LogRecordsRejected',1,$2,$3,$4) ON CONFLICT DO NOTHING`, b.ID, seg.ID, b.End, payload); e != nil {
				return e
			}
		}

		accepted = true
		return q.AdvanceSegment(ctx, dbgen.AdvanceSegmentParams{ID: seg.ID, SourceOffset: b.End, Dropping: b.Dropping, SourceName: seg.Path, Anchor: b.Anchor})
	})
	if err != nil || !accepted {
		return err
	}

	rejected := "resolved"
	if b.Invalid+b.Schema+b.Oversize > 0 {
		rejected = "firing"
	}
	if e := alertOutcome(sc, "LogRecordsChanged", seg.ID, "records", rejected, 0); e != nil {
		return e
	}
	if b.LagKnown {
		lagState := "resolved"
		if b.LagSeconds >= 60 {
			lagState = "firing"
		}
		if e := alertOutcome(sc, "IngestionLagChanged", seg.ID, "lag", lagState, b.LagSeconds); e != nil {
			return e
		}
	}
	if e := alertOutcome(sc, "LogPipelineChanged", "local-log-volume", "pipeline", "resolved", 0); e != nil {
		return e
	}
	return nil
}
func (s *Store) QueryWithin(sc transaction.Scope, f stats.Filter) (out []domain.Bucket, at time.Time, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := dbgen.New(tx).QueryBuckets(ctx, dbgen.QueryBucketsParams{Sites: f.SiteIDs, FromTime: pgtype.Timestamptz{Time: f.From, Valid: true}, ToTime: pgtype.Timestamptz{Time: f.To, Valid: true}, Route: f.Route, Method: f.Method, StatusClass: int32(f.StatusClass), ConfigID: f.ConfigID})
		if e != nil {
			return e
		}
		if len(rows) > 4096 {
			return domain.ErrCapacity
		}
		for _, r := range rows {
			b := domain.Bucket{Minute: r.Minute.Time, SiteID: r.SiteID, Route: r.Route, Method: r.Method, StatusClass: int(r.StatusClass), ConfigID: r.ConfigID, Count: r.Requests, Micros: r.Micros, Bytes: r.Bytes}
			copy(b.Histogram[:], r.Histogram)
			out = append(out, b)
			if r.IngestedAt.Time.After(at) {
				at = r.IngestedAt.Time
			}
		}
		return nil
	})
	return
}

// Failure durably exposes bounded, body-free operational events for O3. It does
// not fabricate successful delivery when the database itself is unavailable.
func (s *Store) Failure(ctx context.Context, p *pgxpool.Pool, reason string, at time.Time) error {
	switch reason {
	case "capacity", "source_changed", "ingest_unavailable", "archive_unavailable", "query_unavailable":
	default:
		return domain.ErrInvalid
	}
	id := "observability/" + reason + "/" + at.UTC().Truncate(time.Minute).Format(time.RFC3339)
	payload, _ := json.Marshal(struct {
		Reason string `json:"reason"`
	}{reason})
	_, e := p.Exec(ctx, `INSERT INTO outbox(event_id,event_type,schema_version,aggregate_id,aggregate_version,payload) VALUES($1,'LogIngestFailed',1,'local-log-volume',1,$2) ON CONFLICT DO NOTHING`, id, payload)
	if e != nil {
		return e
	}
	kind := "LogPipelineChanged"
	if reason == "archive_unavailable" {
		kind = "ArchivePipelineChanged"
	}
	if reason == "query_unavailable" {
		kind = "QueryPipelineChanged"
	}
	return platform.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		return alertOutcome(sc, kind, "local-log-volume", "pipeline", "firing", 0)
	})
}

func sourceNode(node string) string {
	if node == "" {
		return "legacy"
	}
	return node
}

func NewNodeScope(nodeID string, epoch uint64) *Store {
	return &Store{nodeID: nodeID, nodeEpoch: epoch}
}
