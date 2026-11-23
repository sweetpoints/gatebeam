package query

import (
	"context"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type ActorRef = stats.ActorRef
type Filter = domain.QueryFilter
type Job struct {
	Coverage         string
	ManifestObjects  int
	ID, State, Error string
	ScanBytes        int64
	Watermark        int64
	ExpiresAt        time.Time
	Truncated        bool
}
type LocalNode struct {
	NodeID string
	Epoch  uint64
}
type NodeTargets interface {
	TargetsWithin(transaction.Scope) ([]LocalNode, error)
}
type Input struct {
	Target  LocalNode
	Job     Job
	Actor   ActorRef
	Filter  Filter
	Objects []domain.Object
	Token   string
}
type Page struct {
	Job    Job
	Rows   []domain.QueryRow
	Cursor string
}
type Security interface {
	RequireWithin(transaction.Scope, ActorRef, []string) error
}
type Jobs interface {
	SubmitWithin(transaction.Scope, ActorRef, Filter) (Job, error)
	FetchWithin(transaction.Scope, string) (Input, []domain.QueryRow, error)
	ClaimWithin(transaction.Scope) (Input, bool, error)
	CompleteWithin(transaction.Scope, Input, []domain.QueryRow, string) error
}
type Engine interface {
	Execute(context.Context, Filter, []domain.Object) ([]domain.QueryRow, error)
}
