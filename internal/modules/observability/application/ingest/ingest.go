package ingest

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Ingestor struct {
	tx     transaction.Runner
	store  Store
	source Source
	spool  Spool
}

func New(tx transaction.Runner, store Store, source Source, spool Spool) *Ingestor {
	return &Ingestor{tx, store, source, spool}
}
func (i *Ingestor) Ingest(ctx context.Context, segment Segment) (out Batch, err error) {
	if locker, ok := i.spool.(interface {
		WithLock(context.Context, func() error) error
	}); ok {
		err = locker.WithLock(ctx, func() error { out, err = i.ingest(ctx, segment); return err })
		return
	}
	return i.ingest(ctx, segment)
}
func (i *Ingestor) ingest(ctx context.Context, segment Segment) (Batch, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var cursor domain.Cursor
	if e := i.tx.Within(ctx, func(sc transaction.Scope) error { var e error; cursor, e = i.store.CursorWithin(sc, segment); return e }); e != nil {
		if errors.Is(e, domain.ErrIncomplete) {
			return Batch{}, nil
		}
		return Batch{}, e
	}
	if segment.Offset != 0 && segment.Offset != cursor.Offset {
		return Batch{}, domain.ErrSourceChanged
	}
	r, e := i.source.Read(ctx, segment, cursor)
	if e != nil {
		return Batch{}, e
	}
	if r.End == cursor.Offset {
		return Batch{}, nil
	}
	if cursor.SegmentID != "" {
		segment.ID = cursor.SegmentID
	}
	id := fmt.Sprintf("%s-%d-%d", segment.ID, cursor.Offset, r.End)
	objects, e := i.spool.Persist(ctx, id, r.Events)
	if e != nil {
		return Batch{}, e
	}
	batch := Batch{NodeID: segment.NodeID, ID: id, SegmentID: segment.ID, SourceChecksum: r.Checksum, Anchor: r.Anchor, Start: cursor.Offset, End: r.End, Dropping: r.Dropping, Invalid: r.Invalid, Schema: r.Schema, Oversize: r.Oversize, Objects: objects, Buckets: domain.Aggregate(r.Events)}

	batch.LagKnown = segment.Size <= r.End
	if segment.Size > r.End && len(r.Events) > 0 {
		batch.LagKnown = true
		newest := r.Events[0].Time
		for _, event := range r.Events {
			if event.Time.After(newest) {
				newest = event.Time
			}
		}
		batch.LagSeconds = max(0, int64(time.Since(newest).Seconds()))
	}
	e = i.tx.Within(ctx, func(sc transaction.Scope) error { return i.store.CommitWithin(sc, segment, batch) })
	return batch, e
}
