//go:build integration

package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	runtimefixture "gatebeam/tests/fixtures/deployment"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

func TestNodeClaimsOnlyOwnWork(t *testing.T) {
	p := testkit.Postgres(t)
	store := New(p)
	runner := postgres.NewRunner(p)
	a := ClaimTarget{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	b := ClaimTarget{NodeID: "22222222-2222-4222-8222-222222222222", Epoch: 1}
	var aID, bID string
	if err := runner.Within(t.Context(), func(sc transaction.Scope) error {
		var err error
		aID, err = store.EnqueueTargetWithin(sc, "deployment.node.apply.v1", "same-logical-release", json.RawMessage(`{}`), a)
		if err != nil {
			return err
		}
		bID, err = store.EnqueueTargetWithin(sc, "deployment.node.apply.v1", "same-logical-release", json.RawMessage(`{}`), b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if aID == bID {
		t.Fatal("fanout collapsed into one node job")
	}
	globalID, err := store.Enqueue(t.Context(), "global.fixture", "shared", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	global, err := store.Claim(t.Context(), "global", time.Minute)
	if err != nil || global.ID != globalID || global.Target.NodeID != "" {
		t.Fatalf("global claimed node work: %+v %v", global, err)
	}
	if _, err = store.ClaimKinds(t.Context(), "legacy", time.Minute, []string{"deployment.node.apply.v1"}); !errors.Is(err, ErrNoJob) {
		t.Fatalf("legacy claimed directed work: %v", err)
	}
	stale := a
	stale.Epoch++
	if _, err = store.ClaimTargetKinds(t.Context(), "stale", stale, time.Minute, []string{"deployment.node.apply.v1"}); !errors.Is(err, ErrNoJob) {
		t.Fatalf("wrong incarnation claimed old work: %v", err)
	}
	for _, node := range []ClaimTarget{a, b} {
		job, err := store.ClaimTargetKinds(t.Context(), node.NodeID, node, time.Minute, []string{"deployment.node.apply.v1"})
		if err != nil || job.Target != node {
			t.Fatalf("node target lost: %+v %v", job, err)
		}
		if err = store.Renew(t.Context(), job.ID, job.LeaseToken, time.Minute); err != nil {
			t.Fatal(err)
		}
		if err = store.Release(t.Context(), job.ID, job.LeaseToken); err != nil {
			t.Fatal(err)
		}
		if err = store.Renew(t.Context(), job.ID, job.LeaseToken, time.Minute); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("released lease renewed: %v", err)
		}
		reclaimed, err := store.ClaimTargetKinds(t.Context(), node.NodeID, node, time.Minute, []string{"deployment.node.apply.v1"})
		if err != nil {
			t.Fatal(err)
		}
		if reclaimed.LeaseToken == job.LeaseToken {
			t.Fatal("old token reused")
		}
		if err = store.Complete(t.Context(), job.ID, job.LeaseToken); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("stale completion accepted")
		}
		if err = store.Release(t.Context(), job.ID, job.LeaseToken); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("stale release accepted")
		}
		if err = store.Complete(t.Context(), reclaimed.ID, reclaimed.LeaseToken); err != nil {
			t.Fatal(err)
		}
		if err = store.Renew(t.Context(), reclaimed.ID, reclaimed.LeaseToken, time.Minute); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("completed lease renewed")
		}
	}
}

func TestWorkerDrainKeepsLocalCleanup(t *testing.T) {
	p := testkit.Postgres(t)
	store := New(p)
	runner := postgres.NewRunner(p)
	target := ClaimTarget{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	sequence := 0
	enqueue := func(kind string) {
		sequence++
		t.Helper()
		if err := runner.Within(t.Context(), func(sc transaction.Scope) error {
			_, err := store.EnqueueTargetWithin(sc, kind, fmt.Sprintf("%s/%d", kind, sequence), json.RawMessage(`{}`), target)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue("observability.node.query.v1")
	query, err := store.ClaimTargetKinds(t.Context(), "local-query", target, 30*time.Second, []string{"observability.node.query.v1"})
	if err != nil {
		t.Fatal(err)
	}
	if query.Deadline.IsZero() || time.Until(query.Deadline) > 31*time.Second {
		t.Fatal("existing query has no bounded deadline")
	}
	store.StopClaims()
	if _, err = store.ClaimKinds(t.Context(), "global", time.Minute, []string{"notification.delivery"}); !errors.Is(err, ErrDraining) {
		t.Fatal("draining worker accepts new global work")
	}
	enqueue("deployment.node.rotate_logs.v1")
	enqueue("observability.node.query.v1")
	if _, err = store.ClaimTargetKinds(t.Context(), "local-query", target, time.Minute, []string{"observability.node.query.v1"}); !errors.Is(err, ErrDraining) {
		t.Fatal("new local query entered while draining")
	}
	cleanup, err := store.ClaimTargetKinds(t.Context(), "cleanup", target, time.Minute, []string{"deployment.node.rotate_logs.v1"})
	if err != nil {
		t.Fatalf("local cleanup stopped with global claims: %v", err)
	}
	if err = store.Complete(t.Context(), query.ID, query.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if err = store.Complete(t.Context(), cleanup.ID, cleanup.LeaseToken); err != nil {
		t.Fatal(err)
	}
}

func TestDirectedQueueRuntimeAPICapability(t *testing.T) {
	p := testkit.Postgres(t)
	roles := runtimefixture.RuntimeRoles(t, p)
	cfg := p.Config().Copy()
	cfg.ConnConfig.User = roles["api"].Name
	cfg.ConnConfig.Password = roles["api"].Password
	apiPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer apiPool.Close()
	target := ClaimTarget{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	store := New(apiPool)
	for range 2 {
		if err = postgres.NewRunner(apiPool).Within(t.Context(), func(sc transaction.Scope) error {
			_, err := store.EnqueueTargetWithin(sc, "deployment.node.apply.v1", "release", json.RawMessage(`{}`), target)
			return err
		}); err != nil {
			t.Fatalf("runtime API cannot idempotently enqueue: %v", err)
		}
	}
	if _, err = store.ClaimTargetKinds(t.Context(), "forbidden-api-executor", target, time.Minute, []string{"deployment.node.apply.v1"}); err == nil {
		t.Fatal("API acquired edge execution capability")
	}
}

func TestNodeExhaustionCannotCrossTargets(t *testing.T) {
	p := testkit.Postgres(t)
	store := New(p)
	target := ClaimTarget{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	var id string
	if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		var err error
		id, err = store.EnqueueTargetWithin(sc, "deployment.node.apply.v1", "exhaustion", json.RawMessage(`{}`), target)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE jobs SET status='running',attempt=max_attempts,deadline=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimKinds(t.Context(), "global", time.Minute, []string{"deployment.node.apply.v1"}); !errors.Is(err, ErrNoJob) {
		t.Fatal(err)
	}
	other := target
	other.Epoch++
	if _, err := store.ClaimTargetKinds(t.Context(), "other-epoch", other, time.Minute, []string{"deployment.node.apply.v1"}); !errors.Is(err, ErrNoJob) {
		t.Fatal(err)
	}
	var status string
	if err := p.QueryRow(t.Context(), `SELECT status FROM jobs WHERE id=$1`, id).Scan(&status); err != nil || status != "running" {
		t.Fatalf("foreign job was exhausted: %s %v", status, err)
	}
	if _, err := store.ClaimTargetKinds(t.Context(), "owner", target, time.Minute, []string{"deployment.node.apply.v1"}); !errors.Is(err, ErrNoJob) {
		t.Fatal(err)
	}
	if err := p.QueryRow(t.Context(), `SELECT status FROM jobs WHERE id=$1`, id).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("owner did not exhaust bounded job: %s %v", status, err)
	}
}

func TestProcessDrainAppliesAcrossIndependentQueueInstances(t *testing.T) {
	p := testkit.Postgres(t)
	now := time.Now()
	state := lifecycle.New(func() time.Time { return now })
	state.SetReady(lifecycle.GlobalJobs, true)
	state.SetReady(lifecycle.LocalCleanup, true)
	ctx := lifecycle.WithState(t.Context(), state)
	target := ClaimTarget{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	if _, e := New(p).Enqueue(ctx, "notification.delivery", "owned", json.RawMessage(`{}`)); e != nil {
		t.Fatal(e)
	}
	if e := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		_, e := New(p).EnqueueTargetWithin(sc, "deployment.node.rotate_logs.v1", "owned", json.RawMessage(`{}`), target)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	state.BeginDrain(now.Add(time.Minute))
	if _, e := New(p).ClaimKinds(ctx, "worker", time.Minute, []string{"notification.delivery"}); !errors.Is(e, ErrDraining) {
		t.Fatal("new queue instance bypassed process drain", e)
	}
	if _, e := New(p).ClaimTargetKinds(ctx, "edge", target, time.Minute, []string{"deployment.node.rotate_logs.v1"}); e != nil {
		t.Fatal("node cleanup lost", e)
	}
	now = now.Add(61 * time.Second)
	if _, e := New(p).ClaimTargetKinds(ctx, "edge", target, time.Minute, []string{"deployment.node.rotate_logs.v1"}); !errors.Is(e, ErrDraining) {
		t.Fatal("cleanup admitted past process deadline", e)
	}
}
