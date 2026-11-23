package parquet

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// WithLock spans persist AND owner cursor commit. Reconciliation takes the same
// inter-process lock, so an object awaiting commit is never mistaken for orphan.
func (w *Writer) WithLock(ctx context.Context, fn func() error) error {
	f, e := os.OpenFile(filepath.Join(w.root, ".owner-lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (w *Writer) Reconcile(ctx context.Context, references func(context.Context) (map[string]bool, error)) error {
	return w.WithLock(ctx, func() error {
		keep, e := references(ctx)
		if e != nil {
			return e
		}
		if len(keep) > w.MaxFiles {
			return domain.ErrCapacity
		}
		if e = reconcileFiles(ctx, w.root, w.MaxFiles, keep, func(path string) (spoolDirectory, error) { return os.Open(path) }); e != nil {
			return e
		}

		d, e := os.Open(w.root)
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	})
}

// Enumeration itself is paged; a callback counter on filepath.WalkDir would run
// only after an entire directory had already been allocated and sorted.
func reconcileFiles(ctx context.Context, root string, maxEntries int, keep map[string]bool, open func(string) (spoolDirectory, error)) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if maxEntries < 1 {
		return domain.ErrCapacity
	}
	remaining := maxEntries - 1
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		directory, e := open(path)
		if e != nil {
			return e
		}
		defer directory.Close()
		for {
			if e := ctx.Err(); e != nil {
				return e
			}
			entries, err := directory.ReadDir(min(spoolScanPage, remaining+1))
			if e := ctx.Err(); e != nil {
				return e
			}
			if err != nil && err != io.EOF {
				return err
			}
			if len(entries) > remaining {
				return domain.ErrCapacity
			}
			remaining -= len(entries)
			// Charge the whole parent page before descending; pending siblings cannot
			// leave uncharged capacity available to their children.
			for _, entry := range entries {
				if e := ctx.Err(); e != nil {
					return e
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return domain.ErrInvalid
				}
				child := filepath.Join(path, entry.Name())
				if entry.IsDir() {
					if depth >= spoolMaxDepth || depth == 3 && !domain.ValidSite(entry.Name()) {
						return domain.ErrCapacity
					}
					if e = visit(child, depth+1); e != nil {
						return e
					}
					if e = os.Remove(child); e != nil && !errors.Is(e, syscall.ENOTEMPTY) && !errors.Is(e, os.ErrNotExist) {
						return e
					}
					continue
				}
				relative, e := filepath.Rel(root, child)
				if e != nil {
					return e
				}
				info, e := entry.Info()
				if e != nil {
					return e
				}
				if !info.Mode().IsRegular() {
					return domain.ErrInvalid
				}
				if relative == ".owner-lock" {
					continue
				}
				if !strings.HasSuffix(relative, ".parquet") && !strings.HasPrefix(entry.Name(), ".pending-") {
					return domain.ErrInvalid
				}
				if keep[filepath.ToSlash(relative)] {
					continue
				}
				if e = os.Remove(child); e != nil {
					return e
				}
			}
			if err == io.EOF {
				return nil
			}
		}
	}
	return visit(root, 0)
}
