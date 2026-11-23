//go:build integration

package status_test

import (
	"context"
	"errors"
	"gatebeam/internal/integration/certificatematerials"
	app "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	deploymentdomain "gatebeam/internal/modules/deployment/domain"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
)

type preparationGuard struct{ tx transaction.Runner }

func (g preparationGuard) Within(ctx context.Context, _ app.ActorRef, fn func(transaction.Scope) error) error {
	return g.tx.Within(ctx, fn)
}
func (preparationGuard) GuardWithin(transaction.Scope) error                           { return nil }
func (preparationGuard) RequireWithin(transaction.Scope, app.ActorRef, []string) error { return nil }
func TestWorkerPreparesFirstTrustStatusBeforeAnyPublication(t *testing.T) {
	f := newStandardFixture(t)
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	guard := preparationGuard{tx}
	repo := certpg.New()
	crypto := certcrypto.Crypto{}
	manager := app.NewManagement(guard, guard, repo, crypto, nil, nil, audit.New())
	trust, e := manager.SaveTrust(context.Background(), app.ActorRef{}, "", 0, f.trust, f.bundle)
	if e != nil {
		t.Fatal(e)
	}
	service := app.New(tx, repo, guard, crypto, nil, nil, jobs.New(p))
	service.SetStatus(f.client)
	refs := []app.MaterialRef{{Kind: "trust", ID: trust.ID, Revision: 1, Purpose: "clientAuth"}}
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error { return service.ValidateMaterialsWithin(sc, refs) }); e == nil {
		t.Fatal("unprobed trust reported ready")
	}
	worker := certificatematerials.Worker{Published: deploymentpg.NewRuntime(p, jobs.New(p), nil), Certificates: service}
	if e = worker.Step(context.Background()); e != nil && !errors.Is(e, deploymentdomain.ErrNotFound) {
		t.Fatal(e)
	}
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error { return service.ValidateMaterialsWithin(sc, refs) }); e != nil {
		t.Fatal("worker failed prepublication trust readiness", e)
	}
	f.expired.Store(true)
	if e = worker.Step(context.Background()); e != nil && !errors.Is(e, deploymentdomain.ErrNotFound) {
		t.Fatal(e)
	}
	// Existing still-valid attestation remains usable until its own bounded expiry;
	// the preparation scheduler does not replace it with a failed probe.
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error { return service.ValidateMaterialsWithin(sc, refs) }); e != nil {
		t.Fatal("valid cached readiness discarded", e)
	}
}
