package postgres

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/platform/jobs"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ChannelWithin(sc transaction.Scope, id string) (c domain.Channel, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var raw []byte
		e := tx.QueryRow(ctx, `SELECT metadata,secret FROM notification_channels WHERE id=$1 FOR SHARE`, id).Scan(&raw, &c.Secret)
		if errors.Is(e, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if e != nil {
			return e
		}
		return json.Unmarshal(raw, &c)
	})
	return
}
func (s *Store) ChannelsWithin(sc transaction.Scope) (out []domain.Channel, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT metadata FROM notification_channels ORDER BY id LIMIT 100`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var c domain.Channel
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			if e = json.Unmarshal(raw, &c); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return
}
func (s *Store) SaveChannelWithin(sc transaction.Scope, c domain.Channel, expected int64) (out domain.Channel, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if c.ID == "" {
			c.ID = uuid.NewString()
		}
		c.Revision = expected + 1
		raw, e := json.Marshal(c)
		if e != nil {
			return e
		}
		var n int64
		if expected == 0 {
			v, e := tx.Exec(ctx, `INSERT INTO notification_channels(id,owner_id,revision,enabled,metadata,secret) SELECT $1,$2,$3,$4,$5,$6 WHERE (SELECT count(*) FROM notification_channels)<100 ON CONFLICT DO NOTHING`, c.ID, c.OwnerID, c.Revision, c.Enabled, raw, c.Secret)
			if e != nil {
				return e
			}
			n = v.RowsAffected()
		} else {
			v, e := tx.Exec(ctx, `UPDATE notification_channels SET revision=$2,enabled=$3,metadata=$4,secret=$5 WHERE id=$1 AND revision=$6 AND owner_id=$7`, c.ID, c.Revision, c.Enabled, raw, c.Secret, expected, c.OwnerID)
			if e != nil {
				return e
			}
			n = v.RowsAffected()
		}
		if n != 1 {
			return domain.ErrConflict
		}
		out = c
		out.Secret = nil
		return nil
	})
	return
}
func (s *Store) TestWithin(sc transaction.Scope, id string) error {
	event := domain.Event{ID: uuid.NewString(), Kind: "channel_test", ResourceID: id, Fingerprint: "test", Version: 1, State: "firing"}
	raw, _ := json.Marshal(event)
	var deliveryID string
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		key := "test/" + event.ID
		if _, e := tx.Exec(ctx, `INSERT INTO notification_incidents(fingerprint,source_version,state,event) VALUES($1,1,'firing',$2)`, key, raw); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `INSERT INTO notification_transitions(id,fingerprint,event) VALUES($1,$2,$3)`, event.ID, key, raw); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `INSERT INTO notification_deliveries(transition_id,channel_id) VALUES($1,$2) RETURNING id`, event.ID, id).Scan(&deliveryID); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]string{"delivery_id": deliveryID})
	_, e := jobs.New(nil).EnqueueWithin(sc, "notification.delivery", deliveryID, payload)
	return e
}

func (s *Store) ActivityWithin(sc transaction.Scope) (out []app.Activity, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT d.id,d.channel_id,d.status,d.attempt,d.reason,t.event FROM notification_deliveries d JOIN notification_transitions t ON t.id=d.transition_id ORDER BY t.created_at DESC,d.id LIMIT 100`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v app.Activity
			var raw []byte
			if e = rows.Scan(&v.ID, &v.ChannelID, &v.Status, &v.Attempt, &v.Reason, &raw); e != nil {
				return e
			}
			if e = json.Unmarshal(raw, &v.Event); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return
}

func (s *Store) IncidentsWithin(sc transaction.Scope) (out []app.IncidentView, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT event->>'kind',state,source_version,(event->>'lag_seconds')::bigint FROM notification_incidents ORDER BY fingerprint LIMIT 100`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v app.IncidentView
			if e = rows.Scan(&v.Kind, &v.State, &v.Version, &v.LagSeconds); e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return
}
