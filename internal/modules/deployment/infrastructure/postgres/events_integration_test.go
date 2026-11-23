//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	dep "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
	"time"
)

func TestNodeInvalidationsFanOutWithoutLegacyClaims(t *testing.T) {
	p := testkit.Postgres(t)
	if _, err := p.Exec(t.Context(), `INSERT INTO deployment_nodes(id,epoch,principal,enabled,registration) VALUES('11111111-1111-4111-8111-111111111111',1,'fixture-a',true,'{}'),('22222222-2222-4222-8222-222222222222',1,'fixture-b',true,'{}')`); err != nil {
		t.Fatal(err)
	}
	queue := jobs.New(p)
	events := dep.NewEvents(queue)
	if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		_, err := events.EnqueueWithin(sc, "deployment.generation", "revocation-event", json.RawMessage(`{"kind":"revocation"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.ClaimKinds(t.Context(), "legacy", time.Minute, []string{"deployment.generation"}); !errors.Is(err, jobs.ErrNoJob) {
		t.Fatal("invalidation escaped into the old queue", err)
	}
	for _, id := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		target := jobs.ClaimTarget{NodeID: id, Epoch: 1}
		job, err := queue.ClaimTargetKinds(t.Context(), id, target, time.Minute, []string{"deployment.node.generation.v1"})
		var payload struct {
			Kind string `json:"kind"`
		}
		decodeErr := json.Unmarshal(job.Payload, &payload)
		if err != nil || job.Target != target || decodeErr != nil || payload.Kind != "revocation" {
			t.Fatalf("owner invalidation not targeted: %+v %v", job, err)
		}
	}
}
