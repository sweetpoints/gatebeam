package parquet

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReconcileOrphansAndInFlightCommitLock(t *testing.T) {
	root := t.TempDir()
	w, e := New(root)
	if e != nil {
		t.Fatal(e)
	}
	objects, e := w.Persist(t.Context(), strings.Repeat("a", 64), []domain.Event{{SiteID: "11111111-1111-4111-8111-111111111111", Time: time.Now()}})
	if e != nil {
		t.Fatal(e)
	}
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- w.WithLock(t.Context(), func() error { close(ready); <-release; return nil }) }()
	<-ready
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	other, _ := New(root)
	if other.Reconcile(ctx, func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil }) == nil {
		t.Fatal("reconcile passed active ingest lock")
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = other.Reconcile(t.Context(), func(context.Context) (map[string]bool, error) { return map[string]bool{objects[0].Key: true}, nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, objects[0].Key)); e != nil {
		t.Fatal("referenced object removed")
	}
	if e = other.Reconcile(t.Context(), func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, objects[0].Key)); !os.IsNotExist(e) {
		t.Fatal("orphan retained", e)
	}
}

func TestReconcileEnumerationStopsAtSharedBudget(t *testing.T) {
	entries := make([]os.DirEntry, 4096)
	for i := range entries {
		entries[i] = entry(t, "orphan.parquet", false, 0)
	}
	reads := []int{}
	closed := 0
	d := &observedDirectory{entries: entries, sizes: &reads, closed: &closed}
	e := reconcileFiles(t.Context(), "root", 3, nil, func(string) (spoolDirectory, error) { return d, nil })
	if !errors.Is(e, domain.ErrCapacity) || len(reads) != 1 || reads[0] != 3 || len(d.entries) != 4093 || closed != 1 {
		t.Fatal("eager or over-budget enumeration", e, reads, len(d.entries), closed)
	}
}
func TestReconcileCancellationAndGlobalDepthBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	reads := []int{}
	closed := 0
	d := &observedDirectory{entries: []os.DirEntry{entry(t, "orphan.parquet", false, 0)}, sizes: &reads, closed: &closed, afterRead: cancel}
	e := reconcileFiles(ctx, "root", 100, nil, func(string) (spoolDirectory, error) { return d, nil })
	if !errors.Is(e, context.Canceled) || len(reads) != 1 || closed != 1 {
		t.Fatal(e, reads, closed)
	}
	opened := false
	e = reconcileFiles(ctx, "root", 100, nil, func(string) (spoolDirectory, error) { opened = true; return d, nil })
	if !errors.Is(e, context.Canceled) || opened {
		t.Fatal("cancelled scan opened directory")
	}
	reads = nil
	closed = 0
	dirs := map[string][]os.DirEntry{"root": {entry(t, "a", true, 0), entry(t, "b", true, 0)}, filepath.Join("root", "a"): {entry(t, "one.parquet", false, 0)}, filepath.Join("root", "b"): {entry(t, "two.parquet", false, 0)}}
	e = reconcileFiles(t.Context(), "root", 4, map[string]bool{"a/one.parquet": true}, func(path string) (spoolDirectory, error) {
		return &observedDirectory{entries: dirs[path], sizes: &reads, closed: &closed}, nil
	})
	if !errors.Is(e, domain.ErrCapacity) || reads[1] != 2 || closed != 3 {
		t.Fatal("subtree reset shared budget", e, reads, closed)
	}
	root := t.TempDir()
	if e = os.MkdirAll(filepath.Join(root, "a", "b", "c", "too-deep"), 0700); e != nil {
		t.Fatal(e)
	}
	e = reconcileFiles(t.Context(), root, 100, nil, func(path string) (spoolDirectory, error) { return os.Open(path) })
	if !errors.Is(e, domain.ErrCapacity) {
		t.Fatal("depth accepted", e)
	}
}
func TestReconcilePreservesUnownedAndRejectsSymlink(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		root := t.TempDir()
		file := filepath.Join(root, "unowned.txt")
		if e := os.WriteFile(file, []byte("keep"), 0600); e != nil {
			t.Fatal(e)
		}
		if symlink {
			if e := os.Symlink(file, filepath.Join(root, "orphan.parquet")); e != nil {
				t.Fatal(e)
			}
			os.Remove(file)
		}
		e := reconcileFiles(t.Context(), root, 100, nil, func(path string) (spoolDirectory, error) { return os.Open(path) })
		if !errors.Is(e, domain.ErrInvalid) {
			t.Fatal("unowned/symlink accepted", symlink, e)
		}
		if !symlink {
			if _, e = os.Stat(file); e != nil {
				t.Fatal("unowned file removed", e)
			}
		}
	}
}
