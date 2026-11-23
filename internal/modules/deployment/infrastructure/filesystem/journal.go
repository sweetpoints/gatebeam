// Package filesystem owns durable local execution state and the cross-process
// executor lock. Database state is intentionally absent from this adapter.
package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Store struct{ root string }

func New(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("absolute controlled runtime root required")
	}
	for _, d := range []string{root, filepath.Join(root, "releases"), filepath.Join(root, "logs")} {
		if e := os.MkdirAll(d, 0700); e != nil {
			return nil, e
		}
		info, e := os.Lstat(d)
		if e != nil || !info.IsDir() {
			return nil, errors.New("runtime directory must not be a symlink")
		}
	}
	return &Store{root}, syncDir(root)
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *Store) Lock(ctx context.Context) (func(), error) {
	return s.lockFile(ctx, "executor.lock")
}

func (s *Store) lockFile(ctx context.Context, name string) (func(), error) {
	f, e := os.OpenFile(filepath.Join(s.root, name), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-tick.C:
		}
	}
}
func (s *Store) Load(ctx context.Context) (j domain.ApplyJournal, err error) {
	if e := ctx.Err(); e != nil {
		return j, e
	}
	f, e := os.Open(filepath.Join(s.root, "journal.json"))
	if errors.Is(e, os.ErrNotExist) {
		return j, nil
	}
	if e != nil {
		return j, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if e = d.Decode(&j); e != nil {
		return j, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return j, errors.New("invalid journal")
	}
	return j, nil
}
func (s *Store) Save(ctx context.Context, j domain.ApplyJournal) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	// Append and fsync every phase before publishing the current checkpoint.
	// An interrupted append never authorizes an OS effect; Load uses the atomic
	// checkpoint, while history retains previous attempts for local diagnosis.
	record, e := json.Marshal(struct {
		At      time.Time           `json:"at"`
		Journal domain.ApplyJournal `json:"journal"`
	}{time.Now().UTC(), j})
	if e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(s.root, "apply-journal.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(append(record, '\n'))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return atomicFile(s.root, "journal.json", b)
}
func atomicFile(dir, name string, data []byte) error {
	f, e := os.CreateTemp(dir, ".write-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(tmp, filepath.Join(dir, name)); e != nil {
		return e
	}
	return syncDir(dir)
}
