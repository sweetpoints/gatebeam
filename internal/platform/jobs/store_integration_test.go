//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"sync"
	"testing"
	"time"
)

func TestExpiredLeaseCannotCommit(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx := context.Background()
	id, err := s.Enqueue(ctx, "lease", "lease", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Claim(ctx, "a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, "UPDATE jobs SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if e := s.Renew(ctx, a.ID, a.LeaseToken, time.Minute); !errors.Is(e, ErrLeaseLost) {
		t.Fatalf("expired lease renewed: %v", e)
	}
	if e := s.Release(ctx, a.ID, a.LeaseToken); !errors.Is(e, ErrLeaseLost) {
		t.Fatalf("expired lease released: %v", e)
	}
	b, err := s.Claim(ctx, "b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.LeaseToken == b.LeaseToken || b.Attempt != 2 {
		t.Fatal("reclaim did not renew ownership")
	}
	if err = s.Complete(ctx, a.ID, a.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale completion: %v", err)
	}
	if err = s.Complete(ctx, b.ID, b.LeaseToken); err != nil {
		t.Fatal(err)
	}
}
func TestEnqueueIdempotencyAndTransactionalAudit(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	w := audit.New()
	r := postgres.NewRunner(p)
	ctx := context.Background()
	a, err := s.Enqueue(ctx, "a", "same", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Enqueue(ctx, "a", "same", json.RawMessage(`{}`))
	if err != nil || a != b {
		t.Fatalf("idempotency %v", err)
	}
	boom := errors.New("rollback")
	var expired transaction.Scope
	err = r.Within(ctx, func(sc transaction.Scope) error {
		expired = sc
		if _, e := s.EnqueueWithin(sc, "a", "rollback", json.RawMessage(`{}`)); e != nil {
			return e
		}
		if e := w.Append(sc, audit.Event{ID: "event", Action: "created", Payload: json.RawMessage(`{}`)}); e != nil {
			return e
		}
		if e := w.Publish(sc, audit.Envelope{ID: "outbox", Type: "created", SchemaVersion: 1, AggregateID: "aggregate", AggregateVersion: 1, Payload: json.RawMessage(`{}`)}); e != nil {
			return e
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	for _, table := range []string{"audit", "outbox"} {
		var n int
		if e := p.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != 0 {
			t.Fatalf("%s rollback: %d %v", table, n, e)
		}
	}
	var n int
	p.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE key='rollback'").Scan(&n)
	if n != 0 {
		t.Fatal("job escaped rollback")
	}
	if _, err = s.EnqueueWithin(expired, "a", "expired", json.RawMessage(`{}`)); !errors.Is(err, postgres.ErrInvalidScope) {
		t.Fatal(err)
	}
	if err = w.Append(nil, audit.Event{}); !errors.Is(err, postgres.ErrInvalidScope) {
		t.Fatal(err)
	}
}
func TestConcurrentClaim(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx := context.Background()
	s.Enqueue(ctx, "a", "concurrent", json.RawMessage(`{}`))
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := 0
	for range 8 {
		wg.Go(func() {
			_, e := s.Claim(ctx, "worker", time.Minute)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				claimed++
			} else if !errors.Is(e, ErrNoJob) {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if claimed != 1 {
		t.Fatalf("claimed %d", claimed)
	}
}

func TestTransactionFailureBoundaries(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	w := audit.New()
	r := postgres.NewRunner(p)
	ctx := context.Background()
	for _, failure := range []string{"audit", "outbox", "job"} {
		err := r.Within(ctx, func(sc transaction.Scope) error {
			if _, e := s.EnqueueWithin(sc, "atomic", failure, json.RawMessage(`{}`)); e != nil {
				return e
			}
			if e := w.Append(sc, audit.Event{ID: failure, Action: "success", Payload: json.RawMessage(`{}`)}); e != nil {
				return e
			}
			if e := w.Publish(sc, audit.Envelope{ID: failure, Type: "event", SchemaVersion: 1, AggregateID: "a", AggregateVersion: 1, Payload: json.RawMessage(`{}`)}); e != nil {
				return e
			}
			switch failure {
			case "audit":
				return w.Append(sc, audit.Event{ID: failure, Action: "duplicate", Payload: json.RawMessage(`{}`)})
			case "outbox":
				return w.Publish(sc, audit.Envelope{ID: failure, Type: "duplicate", SchemaVersion: 1, AggregateID: "a", AggregateVersion: 1, Payload: json.RawMessage(`{}`)})
			default:
				_, e := s.EnqueueWithin(sc, "", "invalid", json.RawMessage(`{}`))
				return e
			}
		})
		if err == nil {
			t.Fatalf("%s failure accepted", failure)
		}
	}
	for _, table := range []string{"jobs", "audit", "outbox"} {
		var n int
		if e := p.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != 0 {
			t.Fatalf("%s: %d %v", table, n, e)
		}
	}
	var committed transaction.Scope
	if e := r.Within(ctx, func(sc transaction.Scope) error {
		committed = sc
		return w.Append(sc, audit.Event{ID: "committed", Action: "success", Payload: json.RawMessage(`{}`)})
	}); e != nil {
		t.Fatal(e)
	}
	if e := w.Append(committed, audit.Event{}); !errors.Is(e, postgres.ErrInvalidScope) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(ctx)
	if e := r.Within(ctx, func(sc transaction.Scope) error {
		cancel()
		if e := w.Append(sc, audit.Event{}); !errors.Is(e, postgres.ErrInvalidScope) {
			t.Fatalf("canceled scope: %v", e)
		}
		return errors.New("cancel")
	}); e == nil {
		t.Fatal("cancellation accepted")
	}
}

func TestLeaseExpiryAndAttemptLimit(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx := context.Background()
	id, e := s.Enqueue(ctx, "limited", "one", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "UPDATE jobs SET max_attempts=1 WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	a, e := s.Claim(ctx, "worker", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "UPDATE jobs SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	if e = s.Complete(ctx, id, a.LeaseToken); !errors.Is(e, ErrLeaseLost) {
		t.Fatal(e)
	}
	if _, e = s.Claim(ctx, "worker", time.Minute); !errors.Is(e, ErrNoJob) {
		t.Fatal(e)
	}
	var status string
	if e = p.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", id).Scan(&status); e != nil || status != "failed" {
		t.Fatalf("exhaustion %s %v", status, e)
	}
}

func TestConcurrentReclaim(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx := context.Background()
	id, e := s.Enqueue(ctx, "reclaim", "race", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	old, e := s.Claim(ctx, "old", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "UPDATE jobs SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan Job, 8)
	for range 8 {
		wg.Go(func() {
			job, e := s.Claim(ctx, "new", time.Minute)
			if e == nil {
				results <- job
			} else if !errors.Is(e, ErrNoJob) {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	close(results)
	var winners []Job
	for job := range results {
		winners = append(winners, job)
	}
	if len(winners) != 1 || winners[0].Attempt != 2 {
		t.Fatalf("reclaim winners: %+v", winners)
	}
	if e = s.Complete(ctx, id, old.LeaseToken); !errors.Is(e, ErrLeaseLost) {
		t.Fatal(e)
	}
	if e = s.Complete(ctx, id, winners[0].LeaseToken); e != nil {
		t.Fatal(e)
	}
}

func TestClaimSkipsLockedExhaustedJob(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exhausted, e := s.Enqueue(ctx, "cleanup", "exhausted", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "UPDATE jobs SET status='running',attempt=max_attempts,deadline=clock_timestamp()-interval '1 second' WHERE id=$1", exhausted); e != nil {
		t.Fatal(e)
	}
	pending, e := s.Enqueue(ctx, "cleanup", "pending", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	lock, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = lock.Rollback(c)
	}()
	var locked string
	if e = lock.QueryRow(ctx, "SELECT id FROM jobs WHERE id=$1 FOR UPDATE", exhausted).Scan(&locked); e != nil {
		t.Fatal(e)
	}
	// The locked transaction owns a pool connection. Prepare another connection
	// before measuring SKIP LOCKED so connection setup is outside that window.
	preparing := time.Now()
	connectionsBefore := p.Stat().NewConnsCount()
	ready, e := p.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	e = ready.Ping(ctx)
	ready.Release()
	if e != nil {
		t.Fatal(e)
	}
	connections := p.Stat().NewConnsCount()
	t.Logf("claim connection preparation: elapsed_ms=%d new_connections=%d", time.Since(preparing).Milliseconds(), connections-connectionsBefore)
	claimCtx, claimCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer claimCancel()
	job, e := s.Claim(claimCtx, "available-worker", time.Minute)
	if e != nil {
		t.Fatalf("claim failed with exhausted row locked (new connections during claim: %d): %v", p.Stat().NewConnsCount()-connections, e)
	}
	if job.ID != pending {
		t.Fatalf("claimed %s, want pending job %s", job.ID, pending)
	}
}

func TestClaimBoundsExhaustionBatch(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := p.Exec(ctx, `INSERT INTO jobs(kind,key,payload,status,attempt,max_attempts,deadline) SELECT 'batch',n::text,'{}'::jsonb,'running',1,1,clock_timestamp()-interval '1 second' FROM generate_series(1,40) n`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Claim(ctx, "worker", time.Minute); !errors.Is(e, ErrNoJob) {
		t.Fatal(e)
	}
	var failed, running int
	if e := p.QueryRow(ctx, "SELECT count(*) FILTER (WHERE status='failed'),count(*) FILTER (WHERE status='running') FROM jobs").Scan(&failed, &running); e != nil {
		t.Fatal(e)
	}
	if failed != 32 || running != 8 {
		t.Fatalf("cleanup batch: failed=%d running=%d, want 32 and 8", failed, running)
	}
}

func TestClaimKindsLeavesForeignWorkAndFencesWithin(t *testing.T) {
	p := testkit.Postgres(t)
	s := New(p)
	ctx := context.Background()
	foreign, e := s.Enqueue(ctx, "pki.issue", "foreign", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	wanted, e := s.Enqueue(ctx, "deployment.apply", "edge", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.ClaimKinds(ctx, "edge", time.Minute, []string{"deployment.apply"})
	if e != nil || j.ID != wanted {
		t.Fatalf("partition: %+v %v", j, e)
	}
	var status string
	if e = p.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", foreign).Scan(&status); e != nil || status != "pending" {
		t.Fatalf("foreign job changed: %s %v", status, e)
	}
	r := postgres.NewRunner(p)
	boom := errors.New("rollback")
	e = r.Within(ctx, func(sc transaction.Scope) error {
		if e := s.CompleteWithin(sc, j.ID, j.LeaseToken); e != nil {
			return e
		}
		return boom
	})
	if !errors.Is(e, boom) {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", j.ID).Scan(&status); e != nil || status != "running" {
		t.Fatalf("completion escaped Scope: %s %v", status, e)
	}
	if _, e = p.Exec(ctx, "UPDATE jobs SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1", j.ID); e != nil {
		t.Fatal(e)
	}
	e = r.Within(ctx, func(sc transaction.Scope) error { return s.CompleteWithin(sc, j.ID, j.LeaseToken) })
	if !errors.Is(e, ErrLeaseLost) {
		t.Fatalf("stale Scope accepted: %v", e)
	}
	if _, e = s.ClaimKinds(ctx, "edge", time.Minute, nil); e == nil {
		t.Fatal("unrestricted empty kinds accepted")
	}
}
