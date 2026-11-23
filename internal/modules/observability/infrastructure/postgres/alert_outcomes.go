package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/platform/outbox"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

// alertOutcome runs only after the owning use case has fenced its source result.
// Its state row and outbox envelope commit with that result in the same Scope.
func alertOutcome(sc transaction.Scope, kind, resource, fingerprint, state string, lag int64) error {
	var event outbox.Event
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		var old string
		key := kind + "/" + resource + "/" + fingerprint
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "observability/outcome/"+key); e != nil {
			return e
		}
		err := tx.QueryRow(ctx, `SELECT version,state FROM observability_alert_outcomes WHERE kind=$1 AND resource_id=$2 AND fingerprint=$3 FOR UPDATE`, kind, resource, fingerprint).Scan(&version, &old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if old == state {
			return nil
		}
		version++
		if _, err = tx.Exec(ctx, `INSERT INTO observability_alert_outcomes(kind,resource_id,fingerprint,version,state) VALUES($1,$2,$3,$4,$5) ON CONFLICT(kind,resource_id,fingerprint) DO UPDATE SET version=excluded.version,state=excluded.state`, kind, resource, fingerprint, version, state); err != nil {
			return err
		}
		body, _ := json.Marshal(struct {
			State       string `json:"state"`
			Fingerprint string `json:"fingerprint"`
			LagSeconds  int64  `json:"lag_seconds"`
		}{state, fingerprint, lag})
		event = outbox.Event{ID: fmt.Sprintf("observability/%s/%d", key, version), Type: kind, Schema: 1, AggregateID: resource, Version: version, Payload: body}
		return nil
	})
	if err != nil || event.ID == "" {
		return err
	}
	return outbox.New().AppendWithin(sc, event)
}
