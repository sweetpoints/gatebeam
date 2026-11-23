package runtime_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type bootCompiler struct{}

func (bootCompiler) Compile(s app.Snapshot, r edge.RuntimeState) (edge.Artifact, error) {
	data := []byte("# " + s.Version + "/" + r.Generation + "\nevents{}")
	h := sha256.New()
	fmt.Fprintf(h, "10:nginx.conf:%d:", len(data))
	h.Write(data)
	id := hex.EncodeToString(h.Sum(nil))
	return edge.Artifact{ID: id, Digest: id, Files: map[string][]byte{"nginx.conf": data}}, nil
}

type bootNative struct{ version string }

func (*bootNative) Validate(_ context.Context, path string) error {
	_, err := os.ReadFile(filepath.Join(path, "nginx.conf"))
	return err
}
func (p *bootNative) Activate(_ context.Context, version string) error {
	p.version = version
	return nil
}
func (p *bootNative) Observe(context.Context) (string, error) { return p.version, nil }
func (*bootNative) RotateLogs(context.Context) error          { return nil }
func (*bootNative) Stop(context.Context) error                { return nil }

type lostReceiptAuthority struct{ *authority }

func (a *lostReceiptAuthority) Within(_ context.Context, _ string, _ edge.Plan, effect func() error) error {
	if err := effect(); err != nil {
		return err
	}
	a.down = true
	return errors.New("database receipt unavailable")
}

func TestConfirmedBootSupervisorSurvivesLostRemoteReceipt(t *testing.T) {
	store, err := fs.New(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	process := &bootNative{version: "old/g1"}
	base := &authority{old: edge.Plan{Snapshot: app.Snapshot{Version: "old"}, Runtime: edge.RuntimeState{Generation: "g1", Now: time.Now().UTC()}}, new: edge.Plan{Snapshot: app.Snapshot{Version: "new"}, Runtime: edge.RuntimeState{Generation: "g2", Now: time.Now().UTC()}}}
	s := edge.NewSupervisor(process, store, store, bootCompiler{}, &lostReceiptAuthority{base})
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	s.SetBootStore(store, node)
	_, err = s.Apply(t.Context(), "new")
	if err == nil {
		t.Fatal("remote receipt failure hidden")
	}
	got, err := store.LoadConfirmed(t.Context(), node)
	if err != nil || got.Manifest.Version != "new/g2" || process.version != "new/g2" {
		t.Fatalf("lost actual local activation: version=%s err=%v", process.version, err)
	}
}

func TestConfirmedBootSupervisorDoesNotConfirmDeniedActivation(t *testing.T) {
	store, _ := fs.New(filepath.Join(t.TempDir(), "runtime"))
	process := &bootNative{version: "old/g1"}
	base := &authority{down: true}
	s := edge.NewSupervisor(process, store, store, bootCompiler{}, base)
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	s.SetBootStore(store, node)
	if _, err := s.Apply(t.Context(), "new"); err == nil {
		t.Fatal("unauthorized activation succeeded")
	}
	if _, err := store.LoadConfirmed(t.Context(), node); err == nil {
		t.Fatal("denied candidate became local startup authority")
	}
}

func TestConfirmedBootDerivedGenerationIsDurable(t *testing.T) {
	store, err := fs.New(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	process := &bootNative{version: "old/g1"}
	base := &authority{old: edge.Plan{Snapshot: app.Snapshot{Version: "old"}, Runtime: edge.RuntimeState{Generation: "renewed-g2", Now: time.Now().UTC(), Materials: map[string]edge.Material{"site": {VersionID: "renewed-cert"}}}}}
	s := edge.NewSupervisor(process, store, store, bootCompiler{}, base)
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	s.SetBootStore(store, node)
	if _, err = s.ApplyDerived(t.Context(), "certificate"); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadConfirmed(t.Context(), node)
	if err != nil || got.Manifest.Version != "old/renewed-g2" || len(got.Manifest.MaterialIDs) != 1 || got.Manifest.MaterialIDs[0] != "renewed-cert" {
		t.Fatalf("derived native generation lost: %+v %v", got.Manifest, err)
	}
}

type uncertainReceiptAuthority struct{ *authority }

func (a *uncertainReceiptAuthority) Within(_ context.Context, _ string, _ edge.Plan, effect func() error) error {
	if err := effect(); err != nil {
		return err
	}
	return errors.New("commit outcome uncertain")
}
func TestLocalReceiptReconcilesWithoutRollback(t *testing.T) {
	store, _ := fs.New(filepath.Join(t.TempDir(), "runtime"))
	process := &bootNative{version: "old/g1"}
	base := &authority{old: edge.Plan{Snapshot: app.Snapshot{Version: "old"}, Runtime: edge.RuntimeState{Generation: "g1", Now: time.Now().UTC()}}, new: edge.Plan{Snapshot: app.Snapshot{Version: "new"}, Runtime: edge.RuntimeState{Generation: "g2", Now: time.Now().UTC()}}}
	supervisor := edge.NewSupervisor(process, store, store, bootCompiler{}, &uncertainReceiptAuthority{base})
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	supervisor.SetBootStore(store, node)
	result, err := supervisor.Apply(t.Context(), "new")
	if err == nil || result.State != "receipt_pending" || process.version != "new/g2" {
		t.Fatalf("remote receipt uncertainty rolled back verified local traffic: %+v %s %v", result, process.version, err)
	}
	bundle, err := store.LoadConfirmed(t.Context(), node)
	if err != nil || bundle.Manifest.Version != "new/g2" {
		t.Fatal("new confirmed baseline replaced by old database projection", err)
	}
}
