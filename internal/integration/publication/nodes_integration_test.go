//go:build integration

package publication_test

import (
	"context"
	"errors"
	"gatebeam/internal/integration/publication"
	"gatebeam/internal/modules/deployment/application/nodes"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	runtimefixture "gatebeam/tests/fixtures/deployment"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nodePeers struct {
	owner *nodes.Service
	refs  []domain.NodeRef
	pools []*pgxpool.Pool
	image string
}

func enrolledPeers(t *testing.T, f *fixture) nodePeers {
	t.Helper()
	roles := runtimefixture.RuntimeRoles(t, f.p)
	owner := nodes.New(repo.New(), time.Now)
	refs := []domain.NodeRef{{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, {ID: "22222222-2222-4222-8222-222222222222", Epoch: 1}}
	image := "sha256:" + strings.Repeat("a", 64)
	peer := nodePeers{owner: owner, refs: refs, image: image}
	for i, ref := range refs {
		cfg := f.p.Config().Copy()
		principal := roles["edge"].Name
		password := roles["edge"].Password
		if i == 1 {
			var schema string
			if err := f.p.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
				t.Fatal(err)
			}
			principal = schema + "_node_b"
			password = "fixture-only"
			quoted := pgx.Identifier{principal}.Sanitize()
			f.exec(t, `CREATE ROLE `+quoted+` LOGIN PASSWORD 'fixture-only';GRANT `+pgx.Identifier{roles["edge"].Name}.Sanitize()+` TO `+quoted)
			t.Cleanup(func() { _, _ = f.p.Exec(context.Background(), `DROP OWNED BY `+quoted+`;DROP ROLE `+quoted) })
		}
		images := map[string]string{}
		protocols := map[string]uint32{}
		for _, role := range []string{"nginx", "management", "background-jobs", "log-query"} {
			images[role] = image
			protocols[role] = 1
		}
		registration := nodes.NodeRegistration{Node: ref, Principal: principal, RuntimeProtocol: 1, BootFormat: 1, BootArtifactID: strings.Repeat("b", 64), BridgeImages: images, RoleProtocols: protocols}
		if err := f.tx.Within(t.Context(), func(sc transaction.Scope) error { _, err := owner.RegisterWithin(sc, registration); return err }); err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User = principal
		cfg.ConnConfig.Password = password
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		peer.pools = append(peer.pools, pool)
	}
	if err := f.tx.Within(t.Context(), func(sc transaction.Scope) error { return owner.ActivateWithin(sc, refs) }); err != nil {
		t.Fatal(err)
	}
	f.pub.SetNodes(owner)
	return peer
}
func nodeExecution(t *testing.T, f *fixture, peer nodePeers, index int) (*publication.Execution, jobs.Job) {
	t.Helper()
	pool := peer.pools[index]
	queue := jobs.New(pool)
	ref := peer.refs[index]
	job, err := queue.ClaimTargetKinds(t.Context(), ref.ID, jobs.ClaimTarget{NodeID: ref.ID, Epoch: ref.Epoch}, time.Minute, []string{"deployment.node.apply.v1"})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := publication.New(postgres.NewRunner(pool), f.access, f.in, f.materials, f.releases, queue, audit.New(), f.ids)
	coordinator.SetNodes(peer.owner)
	execution := publication.NewExecution(coordinator, queue, job, runtimeSource{}, nginx.Compiler{})
	execution.SetNode(ref, peer.image)
	return execution, job
}

func TestReleaseWaitsForBothNodesBeforeAdvancingOwnerHeads(t *testing.T) {
	for _, outcome := range []string{"both-success", "second-failure"} {
		t.Run(outcome, func(t *testing.T) {
			f := setup(t)
			peers := enrolledPeers(t, f)
			site := f.site(t, "node-publication")
			f.grant(t, f.publisher, site.ID)
			candidate, err := f.pub.Prepare(t.Context(), f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.pub.Publish(t.Context(), f.publisher, candidate.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = jobs.New(f.p).ClaimKinds(t.Context(), "legacy", time.Minute, []string{"deployment.apply"}); !errors.Is(err, jobs.ErrNoJob) {
				t.Fatal("node publish also queued a legacy application", err)
			}
			first, _ := nodeExecution(t, f, peers, 0)
			plan, err := first.Prepare(t.Context(), candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = first.Within(t.Context(), candidate.ID, plan, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			view, err := f.pub.Version(t.Context(), f.admin, candidate.ID)
			if err != nil || view.Effective || view.NodeProgress == nil || view.NodeProgress.State != "partial_success" {
				t.Fatalf("one node globally acknowledged: %+v %v", view, err)
			}
			var published int64
			if err = f.p.QueryRow(t.Context(), `SELECT coalesce(published_revision,0) FROM ingress_sites WHERE id=$1`, site.ID).Scan(&published); err != nil || published != 0 {
				t.Fatal("heads advanced before the second real receipt", err)
			}
			second, _ := nodeExecution(t, f, peers, 1)
			if outcome == "second-failure" {
				err = second.RecordFailure(t.Context(), candidate.ID, edge.ApplyResult{State: "failed", Cause: "native_validation_failed"})
			} else {
				secondPlan, e := second.Prepare(t.Context(), candidate.ID)
				if e != nil {
					t.Fatal(e)
				}
				err = second.Within(t.Context(), candidate.ID, secondPlan, func() error { return nil })
			}
			if err != nil {
				t.Fatal(err)
			}
			view, err = f.pub.Version(t.Context(), f.admin, candidate.ID)
			if err != nil {
				t.Fatal(err)
			}
			if outcome == "second-failure" {
				if view.Effective || view.NodeProgress.State != "partial_success" || view.NodeProgress.Failed != 1 {
					t.Fatalf("partial failure hidden: %+v", view)
				}
			} else if !view.Effective || view.State != domain.Succeeded || view.NodeProgress.Succeeded != 2 {
				t.Fatalf("two independent receipts did not finalize: %+v", view)
			}
		})
	}
}

func TestLocalReceiptReconcilesWithoutRollbackAndWithoutOldPublisherSession(t *testing.T) {
	f := setup(t)
	peers := enrolledPeers(t, f)
	site := f.site(t, "node-reconcile")
	f.grant(t, f.publisher, site.ID)
	candidate, err := f.pub.Prepare(t.Context(), f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pub.Publish(t.Context(), f.publisher, candidate.ID); err != nil {
		t.Fatal(err)
	}
	execution, _ := nodeExecution(t, f, peers, 0)
	plan, err := execution.Prepare(t.Context(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := (nginx.Compiler{}).Compile(plan.Snapshot, plan.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	store, err := fs.New(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: peers.refs[0], ArtifactID: artifact.ID, Version: candidate.ID + "/" + plan.Runtime.Generation, Generation: plan.Runtime.Generation, AuthorizationID: candidate.ID, CreatedAt: plan.Runtime.Now}, Files: artifact.Files, Plan: plan}
	if err = store.StageConfirmed(t.Context(), bundle); err != nil {
		t.Fatal(err)
	}
	if err = store.Confirm(t.Context(), edge.BootEvidence{Node: peers.refs[0], ArtifactID: artifact.ID, Version: bundle.Manifest.Version, Generation: plan.Runtime.Generation, VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	bundle, err = store.LoadConfirmed(t.Context(), peers.refs[0])
	if err != nil {
		t.Fatal(err)
	}
	// The complete local/native authority exists, but its remote receipt never
	// committed. Expiration now cannot erase the fact of the earlier valid load.
	f.exec(t, `UPDATE identity_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id=$1`, f.publisher.CredentialID)
	if err = execution.ReconcileLocal(t.Context(), bundle, bundle.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	if err = execution.ReconcileLocal(t.Context(), bundle, bundle.Manifest.Version); err != nil {
		t.Fatalf("fact replay is not idempotent: %v", err)
	}
	current, err := execution.CurrentVerified(t.Context())
	if err != nil || current.Snapshot.Version != candidate.ID {
		t.Fatalf("recovery selected the old global projection: %+v %v", current, err)
	}
	var globalCount int
	if err = f.p.QueryRow(t.Context(), `SELECT count(*) FROM deployment_runtime`).Scan(&globalCount); err != nil || globalCount != 0 {
		t.Fatal("one local fact fabricated the second node's receipt", err)
	}
	if err = f.tx.Within(t.Context(), func(sc transaction.Scope) error { return peers.owner.SetStatusWithin(sc, peers.refs[0], "revoked") }); err != nil {
		t.Fatal(err)
	}
	if err = execution.ReconcileLocal(t.Context(), bundle, bundle.Manifest.Version); err == nil {
		t.Fatal("revoked node used local authority to regain control rights")
	}
}

type capturedTransactionRunner struct {
	transaction.Runner
	active *transaction.Scope
}

func (r capturedTransactionRunner) Within(ctx context.Context, fn func(transaction.Scope) error) error {
	return r.Runner.Within(ctx, func(sc transaction.Scope) error {
		previous := *r.active
		*r.active = sc
		defer func() { *r.active = previous }()
		return fn(sc)
	})
}

func TestNodeLocalConfirmationRechecksLeaseAfterNativeVerification(t *testing.T) {
	f := setup(t)
	peers := enrolledPeers(t, f)
	site := f.site(t, "node-lease-confirm")
	f.grant(t, f.publisher, site.ID)
	candidate, err := f.pub.Prepare(t.Context(), f.admin, []string{site.ID}, map[string]int64{"site:" + site.ID: site.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pub.Publish(t.Context(), f.publisher, candidate.ID); err != nil {
		t.Fatal(err)
	}
	queue := jobs.New(peers.pools[0])
	ref := peers.refs[0]
	job, err := queue.ClaimTargetKinds(t.Context(), ref.ID, jobs.ClaimTarget{NodeID: ref.ID, Epoch: ref.Epoch}, time.Minute, []string{"deployment.node.apply.v1"})
	if err != nil {
		t.Fatal(err)
	}
	var active transaction.Scope
	runner := capturedTransactionRunner{Runner: postgres.NewRunner(peers.pools[0]), active: &active}
	coordinator := publication.New(runner, f.access, f.in, f.materials, f.releases, queue, audit.New(), f.ids)
	coordinator.SetNodes(peers.owner)
	execution := publication.NewExecution(coordinator, queue, job, runtimeSource{}, nginx.Compiler{})
	execution.SetNode(ref, peers.image)
	plan, err := execution.Prepare(t.Context(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, effectReached := false, false
	err = execution.Within(t.Context(), candidate.ID, plan, func() error {
		// Arm the original short lease only after preparation and the initial
		// authority checks. Use the real held transaction, so no second connection
		// blocks behind its job-row fence and no product clock is replaced.
		if err := postgres.Use(active, func(ctx context.Context, tx pgx.Tx) error {
			changed, err := tx.Exec(ctx, `UPDATE jobs SET deadline=clock_timestamp()+interval '300 milliseconds' WHERE id=$1 AND lease_token=$2 AND status='running'`, job.ID, job.LeaseToken)
			if err == nil && changed.RowsAffected() != 1 {
				return errors.New("owned lease was not armed")
			}
			return err
		}); err != nil {
			return err
		}
		effectReached = true
		time.Sleep(350 * time.Millisecond)
		return execution.ConfirmLocal(t.Context(), func() error { confirmed = true; return nil })
	})
	if !effectReached || !errors.Is(err, jobs.ErrLeaseLost) || confirmed {
		t.Fatal("expired native execution did not refuse local startup authority after its effect", err, effectReached, confirmed)
	}
	var count int
	if err = f.p.QueryRow(t.Context(), `SELECT count(*) FROM deployment_node_runtime`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired lease left a node receipt", err)
	}
}
