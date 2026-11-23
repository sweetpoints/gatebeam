// Package audit persists audit and outbox records in the caller's transaction.
package audit

import (
	"context"
	"encoding/json"
	"gatebeam/internal/platform/audit/dbgen"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type Event struct {
	ID, Action, ActorID string
	Payload             json.RawMessage
}
type Envelope struct {
	ID, Type         string
	SchemaVersion    int32
	AggregateID      string
	AggregateVersion int64
	Payload          json.RawMessage
}
type Writer struct{}

func New() *Writer { return &Writer{} }
func (w *Writer) Append(sc transaction.Scope, event Event) error {
	return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		return dbgen.New(tx).AppendEvent(ctx, dbgen.AppendEventParams{ID: event.ID, Action: event.Action, ActorID: event.ActorID, Payload: event.Payload})
	})
}
func (w *Writer) Publish(sc transaction.Scope, event Envelope) error {
	return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		return dbgen.New(tx).Publish(ctx, dbgen.PublishParams{EventID: event.ID, EventType: event.Type, SchemaVersion: event.SchemaVersion, AggregateID: event.AggregateID, AggregateVersion: event.AggregateVersion, Payload: event.Payload})
	})
}
