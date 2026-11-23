//go:build integration

package notificationevents_test

import (
	"errors"
	"fmt"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/application/alerts"
	notifications "gatebeam/internal/modules/notification/infrastructure/postgres"
	"gatebeam/internal/modules/observability/application/ingest"
	observations "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/outbox"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"strings"
	"testing"
)

func TestOwnerCommitThroughOutboxConsumerQueuesSeparateTransitions(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	source := observations.New()
	sink := notifications.New()
	consumer := alerts.New(tx, sink, sink)
	segment := ingest.Segment{ID: strings.Repeat("a", 64), Path: "access.log", Fingerprint: "owned", Size: 20}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := source.CursorWithin(sc, segment); return e }); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		_, e := sink.SaveChannelWithin(sc, app.Channel{ID: "local-test", OwnerID: "owner", Kind: "telegram", Enabled: true, System: true, Secret: []byte("fixture-only")}, 0)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	batches := []ingest.Batch{{ID: "first", SegmentID: segment.ID, SourceChecksum: "first", Start: 0, End: 10, Invalid: 1, LagKnown: true, LagSeconds: 120}, {ID: "second", SegmentID: segment.ID, SourceChecksum: "second", Start: 10, End: 20, LagKnown: true}}
	for _, b := range batches {
		if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return source.CommitWithin(sc, segment, b) }); e != nil {
			t.Fatal(e)
		}
		if e := consumer.Consume(t.Context()); e != nil {
			t.Fatal(e)
		}
		if e := consumer.Consume(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
	var transitions, jobs, receipts int
	if e := p.QueryRow(t.Context(), `SELECT count(*) FROM notification_transitions`).Scan(&transitions); e != nil || transitions != 4 {
		t.Fatal(transitions, e)
	}
	if e := p.QueryRow(t.Context(), `SELECT count(*) FROM jobs WHERE kind='notification.delivery'`).Scan(&jobs); e != nil || jobs != 4 {
		t.Fatal(jobs, e)
	}
	if e := p.QueryRow(t.Context(), `SELECT count(*) FROM consumer_receipts WHERE consumer='notification/v1'`).Scan(&receipts); e != nil || receipts != 5 {
		t.Fatal(receipts, e)
	}
	// An old batch replay cannot emit a newer failure after the clean batch.
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { return source.CommitWithin(sc, segment, batches[0]) }); e != nil {
		t.Fatal(e)
	}
	if e := consumer.Consume(t.Context()); e != nil {
		t.Fatal(e)
	}
	var firing int
	if e := p.QueryRow(t.Context(), `SELECT count(*) FROM notification_incidents WHERE state='firing'`).Scan(&firing); e != nil || firing != 0 {
		t.Fatal("old batch revived incident", firing, e)
	}
}

type failSecondApply struct {
	store   *notifications.Store
	failure error
}

func (r failSecondApply) ApplyWithin(sc transaction.Scope, e app.Event) error {
	if err := r.store.ApplyWithin(sc, e); err != nil {
		return err
	}
	if e.ID == "consume-second" {
		return r.failure
	}
	return nil
}
func TestConsumerReadReceiptIncidentAndJobsRollbackTogether(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	store := notifications.New()
	if err := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if _, err := store.SaveChannelWithin(sc, app.Channel{ID: "rollback-channel", OwnerID: "owner", Kind: "telegram", Enabled: true, System: true, Secret: []byte("fixture-only")}, 0); err != nil {
			return err
		}
		for i, state := range []string{"firing", "resolved"} {
			id := []string{"consume-first", "consume-second"}[i]
			body := []byte(fmt.Sprintf(`{"state":%q,"fingerprint":"pipeline","lag_seconds":0}`, state))
			if err := outbox.New().AppendWithin(sc, outbox.Event{ID: id, Type: "LogPipelineChanged", Schema: 1, AggregateID: "owned-source", Version: int64(i + 1), Payload: body}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected second apply failure")
	if err := alerts.New(tx, failSecondApply{store, injected}, store).Consume(t.Context()); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	for _, table := range []string{"consumer_receipts", "notification_incidents", "notification_transitions", "notification_deliveries", "jobs"} {
		var count int
		if err := p.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial consumer transaction", table, count, err)
		}
	}
	consumer := alerts.New(tx, store, store)
	for range 2 {
		if err := consumer.Consume(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"consumer_receipts", "notification_transitions", "notification_deliveries", "jobs"} {
		var count int
		if err := p.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 2 {
			t.Fatal("recovery lost or duplicated work", table, count, err)
		}
	}
}
