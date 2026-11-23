package postgres

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/modules/notification/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/outbox"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type Store struct{}

func New() *Store { return &Store{} }

const Consumer = "notification/v1"

func (s *Store) ApplyWithin(sc transaction.Scope, e domain.Event) error {
	fresh, err := outbox.New().ReceiptWithin(sc, Consumer, e.ID)
	if err != nil || !fresh {
		return err
	}
	var ids []string
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		key := e.Kind + "/" + e.ResourceID + "/" + e.Fingerprint
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "notification/"+key); err != nil {
			return err
		}
		q := dbgen.New(tx)
		v, err := q.LockIncident(ctx, key)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		i := domain.Incident{Version: v.SourceVersion, State: v.State}
		changed := i.Observe(e.Version, e.State)
		if e.Version < i.Version {
			return nil
		}
		if v.SourceVersion >= e.Version {
			return nil
		}
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err = q.SaveIncident(ctx, dbgen.SaveIncidentParams{Fingerprint: key, SourceVersion: e.Version, State: e.State, Event: body}); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if err = q.SaveTransition(ctx, dbgen.SaveTransitionParams{ID: e.ID, Fingerprint: key, Event: body}); err != nil {
			return err
		}
		if err = q.QueueTransition(ctx, e.ID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM notification_deliveries WHERE transition_id=$1`, e.ID)
		if err != nil {
			return err
		}
		ids = []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		body, _ := json.Marshal(map[string]string{"delivery_id": id})
		if _, err = jobs.New(nil).EnqueueWithin(sc, "notification.delivery", id, body); err != nil {
			return err
		}
	}
	return nil
}

// PendingWithin adapts platform persistence to the consumer-owned envelope port.
// The caller supplies the same Scope subsequently used by ApplyWithin.
func (s *Store) PendingWithin(sc transaction.Scope, consumer string, kinds []string) ([]app.SourceEvent, error) {
	events, err := outbox.New().PendingWithin(sc, consumer, kinds)
	if err != nil {
		return nil, err
	}
	result := make([]app.SourceEvent, 0, len(events))
	for _, event := range events {
		result = append(result, app.SourceEvent{ID: event.ID, Type: event.Type, AggregateID: event.AggregateID, Version: event.Version, Schema: event.Schema, Payload: event.Payload})
	}
	return result, nil
}
