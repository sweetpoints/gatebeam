// Package audit records administrative actions within the authority transaction.
package audit

import (
	"context"
	"encoding/json"

	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/transaction"

	"github.com/jackc/pgx/v5"
)

type Event struct {
	ID, Action, ActorID string
	Payload             json.RawMessage
}

type Writer struct{}

func New() *Writer { return &Writer{} }

func (*Writer) Append(sc transaction.Scope, event Event) error {
	return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO audit (id, action, actor_id, payload) VALUES ($1, $2, $3, $4)",
			event.ID, event.Action, event.ActorID, event.Payload)
		return err
	})
}
