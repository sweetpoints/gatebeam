package audit

import (
	"context"
	"errors"
	"gatebeam/internal/platform/audit/dbgen"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"time"
)

// Metadata has no payload field. Identity owns the current administrator check;
// this platform port exposes only the bounded public audit projection in Scope.
type Metadata struct {
	ID, ActorID, Action string
	OccurredAt          time.Time
}
type Reader struct{}

func NewReader() *Reader { return &Reader{} }
func (*Reader) RecentWithin(sc transaction.Scope, limit, offset int32) (out []Metadata, err error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return nil, errors.New("invalid audit page")
	}
	out = []Metadata{}
	err = postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := dbgen.New(tx).RecentMetadata(ctx, dbgen.RecentMetadataParams{Limit: limit, Offset: offset})
		if e != nil {
			return e
		}
		for _, r := range rows {
			out = append(out, Metadata{ID: r.ID, ActorID: r.ActorID, Action: r.Action, OccurredAt: r.OccurredAt.Time})
		}
		return nil
	})
	return
}
