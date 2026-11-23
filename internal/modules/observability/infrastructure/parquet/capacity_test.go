package parquet

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

type observedDirectory struct {
	entries   []os.DirEntry
	sizes     *[]int
	closed    *int
	afterRead func()
}

func (d *observedDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	*d.sizes = append(*d.sizes, n)
	if d.afterRead != nil {
		d.afterRead()
	}
	if n <= 0 {
		return nil, errors.New("unbounded directory read")
	}
	n = min(n, len(d.entries))
	out := d.entries[:n]
	d.entries = d.entries[n:]
	if len(out) == 0 {
		return out, io.EOF
	}
	return out, nil
}
func (d *observedDirectory) Close() error { *d.closed++; return nil }
func entry(t *testing.T, name string, directory bool, size int) os.DirEntry {
	t.Helper()
	mode := fs.FileMode(0600)
	if directory {
		mode = fs.ModeDir | 0700
	}
	m := fstest.MapFS{name: &fstest.MapFile{Mode: mode, Data: make([]byte, size)}}
	info, e := fs.Stat(m, name)
	if e != nil {
		t.Fatal(e)
	}
	return fs.FileInfoToDirEntry(info)
}
func TestScanRejectsOverfullDirectoryWithoutEnumeratingIt(t *testing.T) {
	entries := make([]os.DirEntry, 4096)
	for i := range entries {
		entries[i] = entry(t, "object", false, 1)
	}
	reads := []int{}
	closed := 0
	d := &observedDirectory{entries: entries, sizes: &reads, closed: &closed}
	e := scanCapacity(context.Background(), "root", 3, 100, func(string) (spoolDirectory, error) { return d, nil })
	if !errors.Is(e, domain.ErrCapacity) || len(reads) != 1 || reads[0] != 3 || len(d.entries) != 4093 || closed != 1 {
		t.Fatalf("scan exceeded budget: err=%v reads=%v unread=%d closed=%d", e, reads, len(d.entries), closed)
	}
}
func TestScanCancellationStopsBetweenPagesAndBeforeOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reads := []int{}
	closed := 0
	d := &observedDirectory{entries: []os.DirEntry{entry(t, "object", false, 1)}, sizes: &reads, closed: &closed, afterRead: cancel}
	e := scanCapacity(ctx, "root", 1000, 100, func(string) (spoolDirectory, error) { return d, nil })
	if !errors.Is(e, context.Canceled) || len(reads) != 1 || reads[0] != spoolScanPage || closed != 1 {
		t.Fatal(e, reads, closed)
	}
	called := false
	e = scanCapacity(ctx, "root", 1000, 100, func(string) (spoolDirectory, error) { called = true; return d, nil })
	if !errors.Is(e, context.Canceled) || called {
		t.Fatal("cancelled scan opened directory", e, called)
	}
}
func TestScanSharesEntryAndByteBudgetsAcrossDirectories(t *testing.T) {
	for _, limits := range []struct {
		entries int
		bytes   int64
	}{{4, 100}, {10, 3}} {
		reads := []int{}
		closed := 0
		dirs := map[string][]os.DirEntry{"root": {entry(t, "a", true, 0), entry(t, "b", true, 0)}, filepath.Join("root", "a"): {entry(t, "one", false, 2)}, filepath.Join("root", "b"): {entry(t, "two", false, 2)}}
		e := scanCapacity(context.Background(), "root", limits.entries, limits.bytes, func(path string) (spoolDirectory, error) {
			return &observedDirectory{entries: dirs[path], sizes: &reads, closed: &closed}, nil
		})
		if limits.entries == 4 && (len(reads) < 2 || reads[1] != 2) {
			t.Fatal("pending parent page was not charged before child enumeration", reads)
		}
		if !errors.Is(e, domain.ErrCapacity) || closed != 3 {
			t.Fatal("subtree reset global budget", limits, e, closed)
		}
	}
}
