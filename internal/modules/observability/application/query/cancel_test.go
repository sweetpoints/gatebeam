package query

import (
	"context"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
	"sync"
	"testing"
	"time"
)

type memoryScope struct{ ctx context.Context }

func (s memoryScope) Context() context.Context { return s.ctx }

type memoryTx struct{}

func (memoryTx) Within(ctx context.Context, f func(transaction.Scope) error) error {
	return f(memoryScope{ctx})
}

type allow struct{}

func (allow) RequireWithin(transaction.Scope, ActorRef, []string) error { return nil }

type cancelJobs struct {
	mu      sync.Mutex
	in      Input
	claimed bool
}

func (j *cancelJobs) SubmitWithin(transaction.Scope, ActorRef, Filter) (Job, error) {
	return Job{}, nil
}
func (j *cancelJobs) FetchWithin(transaction.Scope, string) (Input, []domain.QueryRow, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.in, nil, nil
}
func (j *cancelJobs) ClaimWithin(transaction.Scope) (Input, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.claimed {
		return Input{}, false, nil
	}
	j.claimed = true
	return j.in, true, nil
}
func (j *cancelJobs) CompleteWithin(transaction.Scope, Input, []domain.QueryRow, string) error {
	return domain.ErrIncomplete
}
func (j *cancelJobs) ListWithin(transaction.Scope, ActorRef, int, int) ([]Input, error) {
	return nil, nil
}
func (j *cancelJobs) CancelWithin(transaction.Scope, string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.in.Job.State = "cancelled"
	return nil
}

type cancelEngine struct{ started, stopped chan struct{} }

func (e cancelEngine) Execute(ctx context.Context, _ Filter, _ []domain.Object) ([]domain.QueryRow, error) {
	close(e.started)
	<-ctx.Done()
	close(e.stopped)
	return nil, ctx.Err()
}
func TestCancellationInterruptsRunningExecutor(t *testing.T) {
	a := ActorRef{UserID: "u", CredentialKind: "session", CredentialID: "c", AuthVersion: 1}
	j := &cancelJobs{in: Input{Job: Job{ID: "j", State: "running", ExpiresAt: time.Now().Add(time.Minute)}, Actor: a, Token: "lease"}}
	service := New(memoryTx{}, allow{}, j)
	engine := cancelEngine{make(chan struct{}), make(chan struct{})}
	coordinator := NewCoordinator(service, engine)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- coordinator.Step(ctx) }()
	<-engine.started
	if e := service.Cancel(ctx, a, "j"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-engine.stopped:
	case <-time.After(350 * time.Millisecond):
		t.Fatal("durable cancel left running executor active")
	}
	if e := <-done; e != nil {
		t.Fatal("cancel treated as pipeline failure", e)
	}
}
