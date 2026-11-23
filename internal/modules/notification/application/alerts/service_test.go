package alerts_test

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/application/alerts"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/platform/transaction"
	"testing"
)

type memoryScope struct{ ctx context.Context }

func (s *memoryScope) Context() context.Context { return s.ctx }

type memoryTransaction struct {
	scope *memoryScope
	calls int
}

func (t *memoryTransaction) Within(ctx context.Context, fn func(transaction.Scope) error) error {
	t.calls++
	t.scope = &memoryScope{ctx}
	return fn(t.scope)
}

type memorySource struct {
	readScope, writeScope transaction.Scope
	event                 domain.Event
	readError             error
}

func (r *memorySource) PendingWithin(sc transaction.Scope, consumer string, kinds []string) ([]app.SourceEvent, error) {
	r.readScope = sc
	if consumer != "notification/v1" || len(kinds) != 9 {
		return nil, errors.New("incorrect source partition")
	}
	if r.readError != nil {
		return nil, r.readError
	}
	return []app.SourceEvent{{ID: "owned-event", Type: "IngestionLagChanged", Schema: 1, AggregateID: "owned-source", Version: 7, Payload: []byte(`{"state":"firing","fingerprint":"lag","lag_seconds":120}`)}}, nil
}
func (r *memorySource) ApplyWithin(sc transaction.Scope, e domain.Event) error {
	r.writeScope = sc
	r.event = e
	return nil
}
func TestConsumerUsesInjectedPendingReaderInSameScope(t *testing.T) {
	tx, r := &memoryTransaction{}, &memorySource{}
	if err := alerts.New(tx, r, r).Consume(t.Context()); err != nil {
		t.Fatal("consumer bypassed supplied persistence boundary", err)
	}
	if tx.calls != 1 || r.readScope != tx.scope || r.writeScope != tx.scope {
		t.Fatal("pending read and apply did not share transaction scope")
	}
	if r.event.ID != "owned-event" || r.event.Kind != "ingestion_lag" || r.event.State != "firing" || r.event.LagSeconds != 120 || r.event.Version != 7 {
		t.Fatal("source envelope mapping changed", r.event)
	}
}
func TestPendingReaderFailureDoesNotApplyEvent(t *testing.T) {
	expected := errors.New("injected pending reader unavailable")
	tx, r := &memoryTransaction{}, &memorySource{readError: expected}
	if err := alerts.New(tx, r, r).Consume(t.Context()); !errors.Is(err, expected) {
		t.Fatal("pending reader error not propagated", err)
	}
	if r.writeScope != nil {
		t.Fatal("event applied after pending read failure")
	}
}
