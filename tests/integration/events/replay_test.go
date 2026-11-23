//go:build integration

package events_test

import (
	"encoding/json"
	"gatebeam/internal/modules/notification/application/alerts"
	repo "gatebeam/internal/modules/notification/infrastructure/postgres"
	"gatebeam/internal/platform/outbox"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
)

func TestOwnerEnvelopeReplayReorderingAndBatchRollback(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	source := outbox.New()
	owner := repo.New()
	consumer := alerts.New(tx, owner, owner)
	latest := outbox.Event{ID: "first-newer", Type: "TargetHealthChanged", Schema: 1, AggregateID: "target", Version: 3, Payload: json.RawMessage(`{"state":"resolved","fingerprint":"health"}`)}
	stale := outbox.Event{ID: "second-older", Type: "TargetHealthChanged", Schema: 2, AggregateID: "target", Version: 1, Payload: json.RawMessage(`{"state":"firing","fingerprint":"health"}`)}
	if err := tx.Within(t.Context(), func(sc transaction.Scope) error {
		for _, event := range []outbox.Event{latest, stale, latest} {
			if err := source.AppendWithin(sc, event); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Consume(t.Context()); err == nil {
		t.Fatal("unknown event schema accepted")
	}
	var receipts, incidents int
	if err := p.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM consumer_receipts),(SELECT count(*) FROM notification_incidents)").Scan(&receipts, &incidents); err != nil || receipts != 0 || incidents != 0 {
		t.Fatal("batch failure escaped transaction", receipts, incidents, err)
	}
	// Correct only the owned fault fixture's unsupported envelope schema, then
	// replay the same durable event IDs. Consumer effects and receipts are atomic.
	if _, err := p.Exec(t.Context(), "UPDATE outbox SET schema_version=1 WHERE event_id=$1", stale.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := consumer.Consume(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	var version int64
	if err := p.QueryRow(t.Context(), "SELECT state,source_version FROM notification_incidents").Scan(&state, &version); err != nil || state != "resolved" || version != 3 {
		t.Fatal("late older event reopened incident", state, version, err)
	}
	if err := p.QueryRow(t.Context(), "SELECT count(*) FROM consumer_receipts WHERE consumer='notification/v1'").Scan(&receipts); err != nil || receipts != 2 {
		t.Fatal("duplicate or missing durable receipt", receipts, err)
	}
}
