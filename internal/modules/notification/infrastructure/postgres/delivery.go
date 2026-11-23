package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/notification/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (s *Store) DueWithin(sc transaction.Scope) (ids []string, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM notification_deliveries WHERE (status='pending' AND next_at<=clock_timestamp()) OR(status='sending' AND deadline<=clock_timestamp()) ORDER BY next_at,id LIMIT 4`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				return e
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return
}
func (s *Store) ClaimWithin(sc transaction.Scope, id string) (d domain.Delivery, c domain.Channel, token string, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var event, metadata []byte
		e := tx.QueryRow(ctx, `SELECT d.id,d.channel_id,d.attempt,t.event,c.metadata,c.secret,c.revision,c.enabled FROM notification_deliveries d JOIN notification_transitions t ON t.id=d.transition_id JOIN notification_channels c ON c.id=d.channel_id WHERE d.id=$1 AND ((d.status='pending' AND d.next_at<=clock_timestamp()) OR (d.status='sending' AND d.deadline<=clock_timestamp())) FOR UPDATE OF d,c SKIP LOCKED`, id).Scan(&d.ID, &d.ChannelID, &d.Attempt, &event, &metadata, &c.Secret, &c.Revision, &c.Enabled)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		secret, revision, enabled := c.Secret, c.Revision, c.Enabled
		if e = json.Unmarshal(metadata, &c); e != nil {
			return e
		}
		c.Secret = secret
		c.Revision = revision
		c.Enabled = enabled
		if e = json.Unmarshal(event, &d.Event); e != nil {
			return e
		}
		// A crashed in-flight attempt is explicitly recorded as unknown, not failure.
		if _, e = tx.Exec(ctx, `UPDATE notification_attempts SET result='commit_unknown',completed_at=clock_timestamp() WHERE delivery_id=$1 AND completed_at IS NULL`, id); e != nil {
			return e
		}
		d.Attempt++
		if d.Attempt > 5 {
			_, e = tx.Exec(ctx, `UPDATE notification_deliveries SET status='failed',reason='attempts_exhausted' WHERE id=$1`, id)
			return e
		}
		if e = tx.QueryRow(ctx, `UPDATE notification_deliveries SET status='sending',attempt=$2,lease_token=gen_random_uuid()::text,deadline=clock_timestamp()+interval '40 seconds' WHERE id=$1 RETURNING lease_token`, id, d.Attempt).Scan(&token); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO notification_attempts(delivery_id,attempt) VALUES($1,$2)`, id, d.Attempt)
		return e
	})
	return
}
func (s *Store) FinishWithin(sc transaction.Scope, d domain.Delivery, revision int64, token, status string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		// Fence lease and current channel revision. Accepted I/O remains accepted if
		// an administrator changed the channel during that already in-flight request.
		reason := status
		var current int64
		if e := tx.QueryRow(ctx, `SELECT revision FROM notification_channels WHERE id=$1 FOR SHARE`, d.ChannelID).Scan(&current); e != nil {
			return e
		}
		if current != revision {
			if status == "sent" {
				reason = "accepted_previous_revision"
			} else {
				status = "pending"
				reason = "channel_changed"
			}
		}
		v, e := tx.Exec(ctx, `UPDATE notification_deliveries SET status=$3,reason=$4,next_at=clock_timestamp()+make_interval(secs=>$5),deadline=NULL,lease_token=NULL WHERE id=$1 AND lease_token=$2 AND status='sending' AND deadline>clock_timestamp()`, d.ID, token, status, reason, domain.RetryAfter(d.Attempt).Seconds())
		if e != nil {
			return e
		}
		if v.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		_, e = tx.Exec(ctx, `UPDATE notification_attempts SET result=$3,completed_at=clock_timestamp() WHERE delivery_id=$1 AND attempt=$2`, d.ID, d.Attempt, reason)
		return e
	})
}
