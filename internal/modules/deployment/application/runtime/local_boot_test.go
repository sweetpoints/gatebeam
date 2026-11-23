package runtime_test

import (
	"bytes"
	"context"
	"errors"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type unchangedBootPolicy struct{}

func (unchangedBootPolicy) Prepare(_ context.Context, b edge.BootBundle, _ time.Time) (edge.BootBundle, error) {
	return b, nil
}

type deniedBootPolicy struct{}

func (deniedBootPolicy) Prepare(context.Context, edge.BootBundle, time.Time) (edge.BootBundle, error) {
	return edge.BootBundle{}, errors.New("unsafe clock or expired material")
}

func TestOfflineBootRejectsCandidateAndUnsafeRestore(t *testing.T) {
	store, err := fs.New(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	process := &bootNative{}
	local := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, time.Now)
	if _, err = local.Start(t.Context(), node); err == nil {
		t.Fatal("empty node booted without initialization")
	}
	plan := (&authority{}).new
	plan.Snapshot.Version = "approved"
	plan.Runtime.Generation = "g1"
	plan.Runtime.Now = time.Now().UTC().Add(-time.Second)
	artifact, _ := (bootCompiler{}).Compile(plan.Snapshot, plan.Runtime)
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", AuthorizationID: "approved", CreatedAt: plan.Runtime.Now}, Files: artifact.Files, Plan: plan}
	if err = store.StageConfirmed(t.Context(), bundle); err != nil {
		t.Fatal(err)
	}
	if _, err = local.Start(t.Context(), node); err == nil {
		t.Fatal("prepared candidate booted")
	}
	if err = store.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got, err := local.Start(t.Context(), node); err != nil || got.Version != "approved/g1" || process.version != "approved/g1" {
		t.Fatalf("confirmed startup requires control: %+v %v", got, err)
	}
	process.version = ""
	denied := edge.NewLocalBoot(process, store, deniedBootPolicy{}, time.Now)
	if _, err = denied.Start(t.Context(), node); err == nil || process.version != "" {
		t.Fatal("unsafe bundle activated")
	}
	node.Epoch++
	if _, err = local.Start(t.Context(), node); err == nil {
		t.Fatal("old epoch snapshot booted")
	}
}

func TestOfflineBootPersistsClockAcrossRestarts(t *testing.T) {
	store, _ := fs.New(filepath.Join(t.TempDir(), "runtime"))
	now := time.Now().UTC()
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	plan := (&authority{}).new
	plan.Snapshot.Version = "approved"
	plan.Runtime.Generation = "g1"
	plan.Runtime.Now = now.Add(-time.Second)
	artifact, _ := (bootCompiler{}).Compile(plan.Snapshot, plan.Runtime)
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", AuthorizationID: "approved", CreatedAt: plan.Runtime.Now}, Files: artifact.Files, Plan: plan}
	if err := store.StageConfirmed(t.Context(), bundle); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", VerifiedAt: now}); err != nil {
		t.Fatal(err)
	}
	process := &bootNative{}
	future := now.Add(time.Hour)
	local := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, func() time.Time { return future })
	if _, err := local.Start(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadConfirmed(t.Context(), node)
	if err != nil || got.CurrentFloor.RecordedAt.Before(future) {
		t.Fatalf("last observed time lost: %+v %v", got.CurrentFloor, err)
	}
	process.version = ""
	rollback := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, func() time.Time { return now.Add(time.Minute) })
	if _, err := rollback.Start(t.Context(), node); err == nil || process.version != "" {
		t.Fatal("restart forgot clock floor")
	}
}

type restrictedBootPolicy struct{}

func (restrictedBootPolicy) Prepare(_ context.Context, b edge.BootBundle, now time.Time) (edge.BootBundle, error) {
	source := b.Plan
	if b.SourcePlan != nil {
		source = *b.SourcePlan
	}
	b.SourcePlan = &source
	b.Plan = source
	b.Plan.Runtime.Generation = "offline-safe"
	b.Plan.Runtime.Now = now
	artifact, err := (bootCompiler{}).Compile(b.Plan.Snapshot, b.Plan.Runtime)
	if err != nil {
		return b, err
	}
	b.Files = artifact.Files
	b.Manifest.ArtifactID = artifact.ID
	b.Manifest.Generation = "offline-safe"
	b.Manifest.Version = b.Plan.Snapshot.Version + "/offline-safe"
	return b, nil
}
func TestOfflineBootPersistsActualRestrictedGeneration(t *testing.T) {
	store, _ := fs.New(filepath.Join(t.TempDir(), "runtime"))
	now := time.Now().UTC()
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	plan := edge.Plan{}
	plan.Snapshot.Version = "approved"
	plan.Runtime.Generation = "g1"
	plan.Runtime.Now = now.Add(-time.Second)
	artifact, _ := (bootCompiler{}).Compile(plan.Snapshot, plan.Runtime)
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", AuthorizationID: "approved", CreatedAt: plan.Runtime.Now}, Files: artifact.Files, Plan: plan}
	if err := store.StageConfirmed(t.Context(), bundle); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", VerifiedAt: now}); err != nil {
		t.Fatal(err)
	}
	process := &bootNative{}
	boot := edge.NewLocalBoot(process, store, restrictedBootPolicy{}, func() time.Time { return now.Add(time.Second) })
	if _, err := boot.Start(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	actual, err := store.LoadConfirmed(t.Context(), node)
	if err != nil || actual.Manifest.Version != process.version || actual.SourcePlan == nil || actual.SourcePlan.Runtime.Generation != "g1" {
		t.Fatalf("restricted actual state or original authorization lost: %+v %v", actual.Manifest, err)
	}
	if _, err = boot.Start(t.Context(), node); err != nil {
		t.Fatalf("confirmed restriction cannot restart: %v", err)
	}
}

// Observe represents the point at which the native process is already serving.
// A crash after this point must not leave a half-advanced security floor.
type floorObservedNative struct {
	bootNative
	floorPath      string
	floorAtObserve []byte
	validations    int
}

func (p *floorObservedNative) Validate(ctx context.Context, path string) error {
	p.validations++
	return p.bootNative.Validate(ctx, path)
}

func (p *floorObservedNative) Observe(ctx context.Context) (string, error) {
	data, err := os.ReadFile(p.floorPath)
	if err != nil {
		return "", err
	}
	p.floorAtObserve = append([]byte(nil), data...)
	return p.bootNative.Observe(ctx)
}

func TestOfflineBootDoesNotAdvanceSecurityFloorAfterServing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	store, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	initial := time.Now().UTC().Truncate(time.Microsecond)
	plan := edge.Plan{}
	plan.Snapshot.Version = "approved"
	plan.Runtime.Generation = "g1"
	plan.Runtime.Now = initial.Add(-time.Second)
	artifact, err := (bootCompiler{}).Compile(plan.Snapshot, plan.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", AuthorizationID: "approved", CreatedAt: plan.Runtime.Now}, Files: artifact.Files, Plan: plan}
	if err = store.StageConfirmed(t.Context(), bundle); err != nil {
		t.Fatal(err)
	}
	if err = store.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: artifact.ID, Version: "approved/g1", Generation: "g1", VerifiedAt: initial}); err != nil {
		t.Fatal(err)
	}

	startTime, observedTime := initial.Add(time.Minute), initial.Add(2*time.Minute)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return startTime
		}
		return observedTime
	}
	process := &floorObservedNative{floorPath: filepath.Join(root, "boot", "floor.json")}
	local := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, clock)
	if _, err = local.Start(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(process.floorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, process.floorAtObserve) {
		t.Fatal("security floor changed after the native process began serving; a kill can split checkpoint and floor writes")
	}
	confirmed, err := store.LoadConfirmed(t.Context(), node)
	if err != nil || !confirmed.VerifiedAt.Equal(observedTime) || !confirmed.CurrentFloor.RecordedAt.Equal(startTime) {
		t.Fatalf("known startup evidence or pre-activation clock floor lost: %v", err)
	}
	// Completion time must still survive restart even though it no longer
	// requires a second two-file security-floor update after activation.
	process.version = ""
	rollback := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, func() time.Time { return initial.Add(90 * time.Second) })
	if _, err = rollback.Start(t.Context(), node); err == nil || process.version != "" {
		t.Fatal("completed startup clock rollback accepted")
	}
	reopened, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &floorObservedNative{floorPath: process.floorPath}
	local = edge.NewLocalBoot(restarted, reopened, unchangedBootPolicy{}, func() time.Time { return observedTime.Add(time.Minute) })
	if _, err = local.Start(t.Context(), node); err != nil {
		t.Fatal("known offline generation did not survive restart", err)
	}
}

func TestOfflineFallbackRetainsCompletedStartupClock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runtime")
	store, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	initial := time.Now().UTC().Truncate(time.Microsecond)
	plan := edge.Plan{}
	plan.Snapshot.Version = "approved"
	plan.Runtime.Now = initial.Add(-time.Second)
	var currentArtifact string
	for i, generation := range []string{"g1", "g2"} {
		plan.Runtime.Generation = generation
		artifact, e := (bootCompiler{}).Compile(plan.Snapshot, plan.Runtime)
		if e != nil {
			t.Fatal(e)
		}
		bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "approved/" + generation, Generation: generation, AuthorizationID: "approved", CreatedAt: plan.Runtime.Now}, Files: artifact.Files, Plan: plan}
		if e = store.StageConfirmed(t.Context(), bundle); e != nil {
			t.Fatal(e)
		}
		if e = store.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: artifact.ID, Version: bundle.Manifest.Version, Generation: generation, VerifiedAt: initial.Add(time.Duration(i) * time.Second)}); e != nil {
			t.Fatal(e)
		}
		currentArtifact = artifact.ID
	}
	startTime, completedTime := initial.Add(time.Minute), initial.Add(2*time.Minute)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return startTime
		}
		return completedTime
	}
	first := &floorObservedNative{floorPath: filepath.Join(root, "boot", "floor.json")}
	if _, err = edge.NewLocalBoot(first, store, unchangedBootPolicy{}, clock).Start(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "releases", currentArtifact, "nginx.conf"), []byte("corrupted current"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first.floorPath)
	if err != nil {
		t.Fatal(err)
	}
	process := &floorObservedNative{floorPath: first.floorPath}
	rollback := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, func() time.Time { return initial.Add(90 * time.Second) })
	if _, err = rollback.Start(t.Context(), node); err == nil || process.validations != 0 || process.version != "" {
		t.Fatal("fallback forgot the current artifact's completed startup time before native validation/activation")
	}
	after, err := os.ReadFile(first.floorPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected fallback changed the trusted floor", err)
	}
	process = &floorObservedNative{floorPath: first.floorPath}
	valid := edge.NewLocalBoot(process, store, unchangedBootPolicy{}, func() time.Time { return completedTime.Add(time.Minute) })
	if _, err = valid.Start(t.Context(), node); err != nil || process.version != "approved/g1" {
		t.Fatal("safe fallback rejected", err)
	}
}
