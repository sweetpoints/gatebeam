// Package outbox owns durable event envelopes and consumer receipts.
package outbox

import (
	"context"
	"encoding/json"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"time"
)

type Event struct {
	ID, Type, AggregateID string
	Version               int64
	Schema                int
	OccurredAt            time.Time
	Payload               json.RawMessage
}
type Store struct{}

func New() *Store { return &Store{} }
func (s *Store) AppendWithin(sc transaction.Scope, e Event) error {
	return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox(event_id,event_type,schema_version,aggregate_id,aggregate_version,payload) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, e.ID, e.Type, e.Schema, e.AggregateID, e.Version, e.Payload)
		return err
	})
}
func (s *Store) ReceiptWithin(sc transaction.Scope, consumer, id string) (fresh bool, err error) {
	err = postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		v, e := tx.Exec(ctx, `INSERT INTO consumer_receipts(consumer,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, consumer, id)
		fresh = v.RowsAffected() == 1
		return e
	})
	return
}
func (s *Store) PendingWithin(sc transaction.Scope, consumer string, types []string) (out []Event, err error) {
	err = postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT event_id,event_type,schema_version,aggregate_id,aggregate_version,occurred_at,payload FROM outbox o WHERE event_type=ANY($1) AND NOT EXISTS(SELECT 1 FROM consumer_receipts r WHERE r.consumer=$2 AND r.event_id=o.event_id) ORDER BY occurred_at,event_id LIMIT 32`, types, consumer)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v Event
			if e = rows.Scan(&v.ID, &v.Type, &v.Schema, &v.AggregateID, &v.Version, &v.OccurredAt, &v.Payload); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return
}
