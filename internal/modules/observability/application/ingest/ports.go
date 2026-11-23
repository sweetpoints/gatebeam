package ingest

import (
	"context"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
)

type Segment = domain.Segment
type Batch = domain.Batch
type Source interface {
	Read(context.Context, Segment, domain.Cursor) (domain.Read, error)
}
type Spool interface {
	Persist(context.Context, string, []domain.Event) ([]domain.Object, error)
}
type Store interface {
	CursorWithin(transaction.Scope, Segment) (domain.Cursor, error)
	CommitWithin(transaction.Scope, Segment, Batch) error
}
