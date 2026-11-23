package filesystem_test

import (
	"bytes"
	"context"
	app "gatebeam/internal/modules/deployment/application"
	runtime "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var bootNode = domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
var bootTime = time.Date(2026, 11, 8, 1, 0, 0, 0, time.UTC)

func bootRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func bootBundle(version, material string) runtime.BootBundle {
	a := artifact("# " + version + "\nevents{}")
	return runtime.BootBundle{
		Manifest: domain.BootManifest{Format: 1, Node: bootNode, ArtifactID: a.ID, Version: version, Generation: "generation-1", AuthorizationID: "authorized-release", CreatedAt: bootTime, MaterialIDs: []string{material}},
		Files:    a.Files,
		Plan:     runtime.Plan{Snapshot: app.Snapshot{Version: version}, Runtime: runtime.RuntimeState{Generation: "generation-1", Now: bootTime}},
	}
}

func bootEvidence(b runtime.BootBundle) runtime.BootEvidence {
	return runtime.BootEvidence{Node: b.Manifest.Node, ArtifactID: b.Manifest.ArtifactID, Version: b.Manifest.Version, Generation: b.Manifest.Generation, VerifiedAt: bootTime.Add(time.Second)}
}

func TestConfirmedBootCrashWindows(t *testing.T) {
	ctx := context.Background()
	root := bootRoot(t)
	s, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	first := bootBundle("release-one", "cert-one")
	if err = s.StageConfirmed(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err = s.LoadConfirmed(ctx, bootNode); err == nil {
		t.Fatal("staging without native confirmation became boot authority")
	}
	if err = s.Confirm(ctx, bootEvidence(first)); err != nil {
		t.Fatal(err)
	}
	second := bootBundle("release-two", "cert-two")
	if err = s.StageConfirmed(ctx, second); err != nil {
		t.Fatal(err)
	}
	// The online current link may switch before actual verification/confirmation.
	if err = s.Switch(ctx, second.Manifest.ArtifactID); err != nil {
		t.Fatal(err)
	}
	reopened, _ := fs.New(root)
	got, err := reopened.LoadConfirmed(ctx, bootNode)
	if err != nil || got.Manifest.Version != "release-one" {
		t.Fatalf("unconfirmed candidate replaced baseline: %s %v", got.Manifest.Version, err)
	}
	bad := bootEvidence(second)
	bad.Generation = "unverified-generation"
	if err = reopened.Confirm(ctx, bad); err == nil {
		t.Fatal("mismatched native evidence accepted")
	}
	if err = reopened.Confirm(ctx, bootEvidence(second)); err != nil {
		t.Fatal(err)
	}
	// No database receipt is present or reachable in this fixture.
	reopened, _ = fs.New(root)
	got, err = reopened.LoadConfirmed(ctx, bootNode)
	if err != nil || got.Manifest.Version != "release-two" || string(got.Files["nginx.conf"]) != "# release-two\nevents{}" {
		t.Fatalf("confirmed local result depends on remote receipt: %v", err)
	}
	if err = os.WriteFile(filepath.Join(root, "releases", second.Manifest.ArtifactID, "nginx.conf"), []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = reopened.LoadConfirmed(ctx, bootNode)
	if err != nil || got.Manifest.Version != "release-one" {
		t.Fatalf("safe previous baseline not recovered: %s %v", got.Manifest.Version, err)
	}
}

func TestBootFloorNeverRegresses(t *testing.T) {
	ctx := context.Background()
	root := bootRoot(t)
	s, _ := fs.New(root)
	first := bootBundle("release-one", "cert-old")
	if err := s.StageConfirmed(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(ctx, bootEvidence(first)); err != nil {
		t.Fatal(err)
	}
	floor := domain.SecurityFloor{Node: bootNode, Sequence: 2, RecordedAt: bootTime.Add(2 * time.Second), RevokedMaterialIDs: []string{"cert-old"}}
	if err := s.RaiseFloor(ctx, floor); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []domain.SecurityFloor{
		{Node: bootNode, Sequence: 1, RecordedAt: bootTime.Add(3 * time.Second)},
		{Node: bootNode, Sequence: 3, RecordedAt: bootTime},
	} {
		if err := s.RaiseFloor(ctx, stale); err == nil {
			t.Fatal("floor or trusted time moved backward")
		}
	}
	if err := s.Confirm(ctx, bootEvidence(first)); err == nil {
		t.Fatal("known revoked material confirmed again")
	}
	floor.Sequence = 3
	floor.RecordedAt = floor.RecordedAt.Add(time.Second)
	floor.RevokedMaterialIDs = []string{"cert-other"}
	if err := s.RaiseFloor(ctx, floor); err != nil {
		t.Fatal(err)
	}
	reopened, _ := fs.New(root)
	got, err := reopened.LoadConfirmed(ctx, bootNode)
	if err != nil || got.CurrentFloor.Sequence != 3 || len(got.CurrentFloor.RevokedMaterialIDs) != 2 {
		t.Fatalf("lost known security constraints: %+v %v", got.CurrentFloor, err)
	}
	other := bootNode
	other.Epoch++
	if _, err = reopened.LoadConfirmed(ctx, other); err == nil {
		t.Fatal("old volume implicitly authorized a new node epoch")
	}
}

func TestBootBundleRejectsUnsafeFiles(t *testing.T) {
	for _, damage := range []string{"traversal", "symlink", "permissions", "missing", "format", "unauthorized", "extra-file", "missing-floor", "root-permissions", "boot-directory-symlink"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			root := bootRoot(t)
			s, _ := fs.New(root)
			b := bootBundle("release-one", "cert-one")
			if damage == "format" {
				b.Manifest.Format = 2
			}
			if damage == "unauthorized" {
				b.Manifest.AuthorizationID = ""
			}
			if damage == "traversal" {
				b.Files["../escape"] = []byte("bad")
			}
			err := s.StageConfirmed(ctx, b)
			if damage == "format" || damage == "unauthorized" || damage == "traversal" {
				if err == nil {
					t.Fatal("unsafe bundle staged")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Confirm(ctx, bootEvidence(b)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "releases", b.Manifest.ArtifactID, "nginx.conf")
			switch damage {
			case "symlink":
				outside := filepath.Join(bootRoot(t), "outside")
				if err = os.WriteFile(outside, b.Files["nginx.conf"], 0600); err == nil {
					err = os.Remove(path)
				}
				if err == nil {
					err = os.Symlink(outside, path)
				}
			case "permissions":
				err = os.Chmod(path, 0644)
			case "missing":
				err = os.Remove(path)
			case "missing-floor":
				err = os.Remove(filepath.Join(root, "boot", "floor.json"))
			case "root-permissions":
				err = os.Chmod(root, 0755)
			case "boot-directory-symlink":
				err = os.Rename(filepath.Join(root, "boot"), filepath.Join(root, "saved-boot"))
				if err == nil {
					err = os.Symlink(filepath.Join(root, "saved-boot"), filepath.Join(root, "boot"))
				}
			case "extra-file":
				err = os.WriteFile(filepath.Join(filepath.Dir(path), "injected.conf"), []byte("bad"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.LoadConfirmed(ctx, bootNode); err == nil {
				t.Fatal("unsafe runtime files used for boot")
			}
		})
	}
}

func TestConfirmedBootStageRetryKeepsImmutableState(t *testing.T) {
	s, _ := fs.New(bootRoot(t))
	b := bootBundle("release-one", "cert-one")
	b.Manifest.CreatedAt = time.Now()
	b.Plan.Runtime.Now = b.Manifest.CreatedAt
	if err := s.StageConfirmed(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := s.StageConfirmed(t.Context(), b); err != nil {
		t.Fatal("retry treated serialized time metadata as a different release", err)
	}
}

func TestBootFloorRejectsRestoredOldFloorFile(t *testing.T) {
	root := bootRoot(t)
	s, _ := fs.New(root)
	b := bootBundle("release-one", "cert-one")
	if err := s.StageConfirmed(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(t.Context(), bootEvidence(b)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "boot", "floor.json")
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RaiseFloor(t.Context(), domain.SecurityFloor{Node: bootNode, Sequence: 1, RecordedAt: bootTime.Add(2 * time.Second), RevokedMaterialIDs: []string{"cert-one"}}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.LoadConfirmed(t.Context(), bootNode); err == nil {
		t.Fatal("restored floor revived known revoked material")
	}
}

func TestConfirmedBootInterruptedWritesFailClosed(t *testing.T) {
	for _, phase := range []string{"staged-file-write", "staged-directory-sync", "confirmation-write", "confirmation-corruption", "floor-checkpoint"} {
		t.Run(phase, func(t *testing.T) {
			root := bootRoot(t)
			s, _ := fs.New(root)
			first := bootBundle("release-one", "cert-one")
			if err := s.StageConfirmed(t.Context(), first); err != nil {
				t.Fatal(err)
			}
			if err := s.Confirm(t.Context(), bootEvidence(first)); err != nil {
				t.Fatal(err)
			}
			next := bootBundle("release-two", "cert-two")
			switch phase {
			case "staged-file-write", "staged-directory-sync":
				tmp := filepath.Join(root, "releases", ".stage-interrupted")
				if err := os.Mkdir(tmp, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(tmp, "nginx.conf"), next.Files["nginx.conf"][:5], 0600); err != nil {
					t.Fatal(err)
				}
			case "confirmation-write":
				if err := s.StageConfirmed(t.Context(), next); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "boot", ".write-interrupted"), []byte(`{"Current":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "confirmation-corruption":
				if err := os.WriteFile(filepath.Join(root, "boot", "confirmed.json"), []byte(`{"Current":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "floor-checkpoint":
				path := filepath.Join(root, "boot", "floor.json")
				old, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = s.RaiseFloor(t.Context(), domain.SecurityFloor{Node: bootNode, Sequence: 1, RecordedAt: bootTime.Add(time.Minute), RevokedMaterialIDs: []string{"cert-one"}}); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, old, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := fs.New(root)
			if err != nil {
				t.Fatal(err)
			}
			got, err := reopened.LoadConfirmed(t.Context(), bootNode)
			if phase == "confirmation-corruption" || phase == "floor-checkpoint" {
				if err == nil {
					t.Fatal("partial security metadata authorized startup")
				}
			} else if err != nil || got.Manifest.Version != "release-one" {
				t.Fatalf("incomplete write replaced complete baseline: %s %v", got.Manifest.Version, err)
			}
		})
	}
}

func TestConfirmedBootRejectsModifiedRuntimePlan(t *testing.T) {
	root := bootRoot(t)
	store, _ := fs.New(root)
	bundle := bootBundle("release-one", "cert-one")
	if err := store.StageConfirmed(t.Context(), bundle); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(t.Context(), bootEvidence(bundle)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "boot", "staged", bundle.Manifest.ArtifactID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"version":"release-one"`), []byte(`"version":"injected-plan"`), 1)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.LoadConfirmed(t.Context(), bootNode); err == nil {
		t.Fatal("modified plan became offline compilation authority")
	}
}

func TestKnownBootConfirmationRejectsChangedAuthority(t *testing.T) {
	for _, scenario := range []string{"unconfirmed-candidate", "different-epoch", "changed-manifest", "changed-metadata", "changed-floor", "revoked-material", "clock-regression"} {
		t.Run(scenario, func(t *testing.T) {
			root := bootRoot(t)
			store, err := fs.New(root)
			if err != nil {
				t.Fatal(err)
			}
			first := bootBundle("release-one", "cert-one")
			if err = store.StageConfirmed(t.Context(), first); err != nil {
				t.Fatal(err)
			}
			if err = store.Confirm(t.Context(), bootEvidence(first)); err != nil {
				t.Fatal(err)
			}
			known, err := store.LoadConfirmed(t.Context(), bootNode)
			if err != nil {
				t.Fatal(err)
			}
			manifest, expected := known.Manifest, known.CurrentFloor
			verifiedAt := bootTime.Add(time.Minute)
			switch scenario {
			case "unconfirmed-candidate":
				next := bootBundle("release-two", "cert-two") // same authorization ID
				if err = store.StageConfirmed(t.Context(), next); err != nil {
					t.Fatal(err)
				}
				manifest = next.Manifest
			case "different-epoch":
				manifest.Node.Epoch++
			case "changed-manifest":
				manifest.MaterialIDs = []string{"substituted-material"}
			case "changed-metadata":
				path := filepath.Join(root, "boot", "staged", manifest.ArtifactID+".json")
				data, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				changed := bytes.Replace(data, []byte(`"version":"release-one"`), []byte(`"version":"injected-plan"`), 1)
				if bytes.Equal(data, changed) {
					t.Fatal("metadata mutation fixture did not change")
				}
				if e = os.WriteFile(path, changed, 0600); e != nil {
					t.Fatal(e)
				}
			case "changed-floor", "revoked-material":
				next := expected
				next.Sequence++
				next.RecordedAt = bootTime.Add(2 * time.Second)
				if scenario == "revoked-material" {
					next.RevokedMaterialIDs = []string{"cert-one"}
				}
				if err = store.RaiseFloor(t.Context(), next); err != nil {
					t.Fatal(err)
				}
				if scenario == "revoked-material" {
					expected = next
				}
			case "clock-regression":
				verifiedAt = known.VerifiedAt.Add(-time.Nanosecond)
			}
			checkpoint := filepath.Join(root, "boot", "confirmed.json")
			floor := filepath.Join(root, "boot", "floor.json")
			beforeCP, e := os.ReadFile(checkpoint)
			if e != nil {
				t.Fatal(e)
			}
			beforeFloor, e := os.ReadFile(floor)
			if e != nil {
				t.Fatal(e)
			}
			if err = store.ConfirmKnown(t.Context(), manifest, expected, verifiedAt); err == nil {
				t.Fatal("unsafe known-boot confirmation accepted")
			}
			afterCP, e := os.ReadFile(checkpoint)
			if e != nil || !bytes.Equal(beforeCP, afterCP) {
				t.Fatal("rejected confirmation rewrote checkpoint", e)
			}
			afterFloor, e := os.ReadFile(floor)
			if e != nil || !bytes.Equal(beforeFloor, afterFloor) {
				t.Fatal("rejected confirmation rewrote floor", e)
			}
		})
	}
}

func TestKnownBootCannotConfirmAnUninitializedNode(t *testing.T) {
	store, err := fs.New(bootRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	candidate := bootBundle("staged-only", "cert-one")
	if err = store.StageConfirmed(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	expected := domain.SecurityFloor{Node: bootNode, RecordedAt: bootTime}
	if err = store.ConfirmKnown(t.Context(), candidate.Manifest, expected, bootTime.Add(time.Second)); err == nil {
		t.Fatal("staged-only node acquired boot authority")
	}
	if _, err = store.LoadConfirmed(t.Context(), bootNode); err == nil {
		t.Fatal("rejected known confirmation created a baseline")
	}
}

func TestOnlineConfirmationRetainsKnownStartupClock(t *testing.T) {
	root := bootRoot(t)
	store, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	first := bootBundle("release-one", "cert-one")
	if err = store.StageConfirmed(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err = store.Confirm(t.Context(), bootEvidence(first)); err != nil {
		t.Fatal(err)
	}
	known, err := store.LoadConfirmed(t.Context(), bootNode)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfirmKnown(t.Context(), known.Manifest, known.CurrentFloor, bootTime.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	candidate := bootBundle("release-two", "cert-two")
	if err = store.StageConfirmed(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	beforeCP, err := os.ReadFile(filepath.Join(root, "boot", "confirmed.json"))
	if err != nil {
		t.Fatal(err)
	}
	beforeFloor, err := os.ReadFile(filepath.Join(root, "boot", "floor.json"))
	if err != nil {
		t.Fatal(err)
	}
	evidence := bootEvidence(candidate)
	evidence.VerifiedAt = bootTime.Add(30 * time.Second)
	if err = store.Confirm(t.Context(), evidence); err == nil {
		t.Fatal("online candidate forgot the completed known startup clock")
	}
	afterCP, err := os.ReadFile(filepath.Join(root, "boot", "confirmed.json"))
	if err != nil || !bytes.Equal(beforeCP, afterCP) {
		t.Fatal("rejected clock rollback rewrote checkpoint", err)
	}
	afterFloor, err := os.ReadFile(filepath.Join(root, "boot", "floor.json"))
	if err != nil || !bytes.Equal(beforeFloor, afterFloor) {
		t.Fatal("rejected clock rollback rewrote floor", err)
	}
}
