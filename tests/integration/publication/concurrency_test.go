//go:build integration

package publication_test

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"sync"
	"testing"
	"time"
)

// Owner queue and platform job mutation share the same real transaction. The
// current-credential and native effect races are covered by the publication
// coordinator and separate-process acceptance, not inferred from this test.
func TestPublicationQueueRollbackConcurrentReplayAndLeaseFence(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	owner := release.New(repo.New(), identifiers.Generator{})
	queue := jobs.New(p)
	var candidate release.Candidate
	if err := tx.Within(t.Context(), func(sc transaction.Scope) error {
		var err error
		candidate, err = owner.PrepareWithin(sc, release.PrepareInput{Snapshot: app.Snapshot{Version: "deployment/v1"}, SelectedSiteIDs: []string{"owned"}, Expected: map[string]int64{"site:owned": 1}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("owned transaction rollback")
	enqueue := func(sc transaction.Scope) error {
		_, fresh, err := owner.QueueWithin(sc, candidate.ID)
		if err != nil || !fresh {
			return err
		}
		_, err = queue.EnqueueWithin(sc, "deployment.apply", candidate.ID, json.RawMessage(`{}`))
		return err
	}
	if err := tx.Within(t.Context(), func(sc transaction.Scope) error {
		if err := enqueue(sc); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var n int
	if err := p.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM jobs)+(SELECT count(*) FROM deployment_releases)").Scan(&n); err != nil || n != 0 {
		t.Fatal("queue escaped rollback", n, err)
	}
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); failures <- tx.Within(t.Context(), enqueue) }()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := p.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM jobs)+(SELECT count(*) FROM deployment_releases)").Scan(&n); err != nil || n != 2 {
		t.Fatal("concurrent replay duplicated state", n, err)
	}
	lease, err := queue.ClaimKinds(t.Context(), "owned-edge", time.Minute, []string{"deployment.apply"})
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := queue.Complete(canceled, lease.ID, lease.LeaseToken); err == nil {
		t.Fatal("canceled completion succeeded")
	}
	if _, err := p.Exec(t.Context(), "UPDATE jobs SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1", lease.ID); err != nil {
		t.Fatal(err)
	}
	replacement, err := queue.ClaimKinds(t.Context(), "replacement-edge", time.Minute, []string{"deployment.apply"})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Complete(t.Context(), lease.ID, lease.LeaseToken); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatal("expired worker completed reclaimed effect", err)
	}
	if err := queue.Complete(t.Context(), replacement.ID, replacement.LeaseToken); err != nil {
		t.Fatal(err)
	}
}
