//go:build integration

package pki_test

import (
	"context"
	pub "gatebeam/internal/integration/publication"
	cert "gatebeam/internal/modules/certificates/application"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	deploypg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	ingress "gatebeam/internal/modules/ingress/application"
	ingresspg "gatebeam/internal/modules/ingress/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// All runtime bytes here are the exact already verified native fixture; only the
// selected managed client is delegated to its real certificate/PKI owner fence.
type nativeMaterialSource struct {
	service *cert.Service
	ref     cert.MaterialRef
	state   edge.RuntimeState
}

func (s nativeMaterialSource) ReadWithin(sc transaction.Scope, _ deploy.Snapshot) (edge.RuntimeState, error) {
	if e := s.service.ValidateMaterialsWithin(sc, []cert.MaterialRef{s.ref}); e != nil {
		return edge.RuntimeState{}, e
	}
	return s.state, nil
}
func nativeRestoreMaterialFence(t *testing.T, db *pgxpool.Pool, service *cert.Service, ref cert.MaterialRef, plan edge.Plan, root, container string) func() {
	t.Helper()
	tx := postgres.NewRunner(db)
	ids := identifiers.Generator{}
	owner := release.New(deploypg.New(), ids)
	snapshot := plan.Snapshot
	snapshot.Version = "deployment/v1"
	snapshot.Targets = append([]deploy.Target(nil), snapshot.Targets...)
	for i := range snapshot.Targets {
		snapshot.Targets[i].Config.Health.Enabled = false
	}
	// A verified logical snapshot is already present in this native fixture.
	var candidate release.Candidate
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
		var e error
		candidate, e = owner.PrepareWithin(sc, release.PrepareInput{Snapshot: snapshot, SelectedSiteIDs: []string{"site"}, Expected: map[string]int64{"site:site": 1}})
		if e != nil {
			return e
		}
		if _, _, e = owner.QueueWithin(sc, candidate.ID); e != nil {
			return e
		}
		artifact, e := (nginx.Compiler{}).Compile(plan.Snapshot, plan.Runtime)
		if e != nil {
			return e
		}
		return owner.RecordVerifiedWithin(sc, candidate.ID, artifact.ID, plan.Snapshot.Version+"/"+plan.Runtime.Generation)
	}); e != nil {
		t.Fatal(e)
	}
	sites := ingress.New(tx, ingresspg.New(), nil, audit.New(), ids)
	coordinator := pub.New(tx, nil, sites, nil, owner, jobs.New(db), audit.New(), ids)
	execution := pub.NewExecution(coordinator, jobs.New(db), jobs.Job{}, nativeMaterialSource{service, ref, plan.Runtime}, nginx.Compiler{})
	restore, e := execution.CurrentVerified(t.Context())
	if e != nil {
		t.Fatal("good native restore plan", e)
	}
	artifact, e := (nginx.Compiler{}).Compile(restore.Snapshot, restore.Runtime)
	if e != nil {
		t.Fatal(e)
	}
	// Stage and activate with Health disabled; the security fence must remain
	// authoritative even when no read-only route probe can reject the identity.
	for name, b := range artifact.Files {
		path := filepath.Join(root, name)
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		write(t, path, b)
	}
	if e = execution.RestoreActivateWithin(t.Context(), restore, func(context.Context) error {
		command(t, "exec", container, "nginx", "-t", "-p", "/gateway/", "-c", "nginx.conf")
		command(t, "exec", container, "nginx", "-s", "reload", "-p", "/gateway/", "-c", "nginx.conf")
		return nil
	}); e != nil {
		t.Fatal("good native restore activation", e)
	}
	expected := restore.Snapshot.Version + "/" + restore.Runtime.Generation
	deadline := time.Now().Add(2 * time.Second)
	for {
		observed := command(t, "exec", container, "wget", "-qO-", "http://127.0.0.1:9090/version")
		if observed == expected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native restore version missing", observed, expected)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() {
		for _, fence := range []func(context.Context, edge.Plan, func(context.Context) error) error{execution.WithRestore, execution.RestoreActivateWithin} {
			if e := fence(t.Context(), restore, func(context.Context) error { t.Fatal("revoked native restore reached effect/receipt"); return nil }); e == nil {
				t.Fatal("revoked native restore guard accepted")
			}
		}
		if e := tx.Within(t.Context(), func(sc transaction.Scope) error {
			_, receipt, e := owner.CurrentVerifiedWithin(sc)
			if e == nil && receipt.Version != plan.Snapshot.Version+"/"+plan.Runtime.Generation {
				t.Fatal("revoked native restore wrote receipt", receipt)
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
		t.Log("actual Nginx restore activated valid managed client with Health disabled; revocation during outside-DB interval denied final restore receipt and subsequent reload")
	}
}
