// Package ocspcache persists bounded original signed responses, never CA keys.
package ocspcache

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/certificates/domain"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var errUnsafe = errors.New("local OCSP cache unavailable")

type Store struct {
	root string
	mu   sync.Mutex
}
type floor struct {
	At      time.Time
	Revoked map[string]bool
}

func NewStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errUnsafe
	}
	created := false
	if err := os.Mkdir(root, 0700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := owned(root, true); err != nil {
		return nil, err
	}
	s := &Store{root: root}
	if created {
		if err := s.write("minimum.json", floor{Revoked: map[string]bool{}}); err != nil {
			return nil, err
		}
		if err := s.write("floor.json", floor{Revoked: map[string]bool{}}); err != nil {
			return nil, err
		}
	}
	var state floor
	if err := s.read("floor.json", &state, 1<<20); err != nil || state.Revoked == nil || len(state.Revoked) > 4096 {
		return nil, errUnsafe
	}
	var minimum floor
	if err := s.read("minimum.json", &minimum, 1<<20); err != nil || minimum.Revoked == nil || state.At.Before(minimum.At) {
		return nil, errUnsafe
	}
	for key, revoked := range minimum.Revoked {
		if !validKey(key) || !revoked || !state.Revoked[key] {
			return nil, errUnsafe
		}
	}
	return s, nil
}
func owned(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errUnsafe
	}
	return nil
}
func validKey(key string) bool {
	b, err := hex.DecodeString(key)
	return err == nil && len(b) == 32 && strings.ToLower(key) == key
}
func (s *Store) locked(ctx context.Context) (func(), error) {
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(s.root, "cache.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			unlock := func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close(); s.mu.Unlock() }
			// No other writer holds the cross-process lock now. Abandoned
			// temp files carry no authority and must not accumulate after crashes.
			entries, err := os.ReadDir(s.root)
			if err != nil {
				unlock()
				return nil, err
			}
			removed := false
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), ".status-") {
					continue
				}
				path := filepath.Join(s.root, entry.Name())
				if err := owned(path, false); err != nil {
					unlock()
					return nil, err
				}
				if err := os.Remove(path); err != nil {
					unlock()
					return nil, err
				}
				removed = true
			}
			if removed {
				dir, err := os.Open(s.root)
				if err != nil {
					unlock()
					return nil, err
				}
				err = dir.Sync()
				_ = dir.Close()
				if err != nil {
					unlock()
					return nil, err
				}
			}
			return unlock, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			file.Close()
			s.mu.Unlock()
			return nil, err
		}
		select {
		case <-ctx.Done():
			file.Close()
			s.mu.Unlock()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func (s *Store) read(name string, v any, limit int64) error {
	path := filepath.Join(s.root, name)
	if err := owned(path, false); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return errUnsafe
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(v); err != nil || decoder.Decode(new(any)) != io.EOF {
		return errUnsafe
	}
	return nil
}
func (s *Store) write(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.root, ".status-")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(path, filepath.Join(s.root, name)); err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Store) Load(ctx context.Context, key string) (domain.CachedStatus, error) {
	var status domain.CachedStatus
	if !validKey(key) {
		return status, errUnsafe
	}
	unlock, err := s.locked(ctx)
	if err != nil {
		return status, err
	}
	defer unlock()
	err = s.read(key+".json", &status, 128<<10)
	return status, err
}
func (s *Store) Save(ctx context.Context, key string, status domain.CachedStatus) error {
	if !validKey(key) || len(status.DER) == 0 || len(status.DER) > 64<<10 || status.ObservedAt.IsZero() {
		return errUnsafe
	}
	unlock, err := s.locked(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	type candidate struct {
		name string
		at   time.Time
		size int64
	}
	var candidates []candidate
	var size int64
	incoming := int64(len(status.DER)*2 + 256)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || name == "floor.json" || name == "minimum.json" || name == key+".json" {
			continue
		}
		if !validKey(strings.TrimSuffix(name, ".json")) {
			return errUnsafe
		}
		if err := owned(filepath.Join(s.root, name), false); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 128<<10 {
			return errUnsafe
		}
		candidates = append(candidates, candidate{name, info.ModTime(), info.Size()})
		size += info.Size()
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].at.Before(candidates[j].at) })
	for len(candidates) >= 1024 || size+incoming > 64<<20 {
		if len(candidates) == 0 {
			return errUnsafe
		}
		if err = os.Remove(filepath.Join(s.root, candidates[0].name)); err != nil {
			return err
		}
		size -= candidates[0].size
		candidates = candidates[1:]
	}
	return s.write(key+".json", status)
}
func (s *Store) Check(ctx context.Context, key string, now time.Time, revoked bool) (bool, error) {
	if !validKey(key) || now.IsZero() {
		return false, errUnsafe
	}
	unlock, err := s.locked(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	var state floor
	if err = s.read("floor.json", &state, 1<<20); err != nil || state.Revoked == nil || now.Before(state.At) {
		return false, errUnsafe
	}
	var minimum floor
	if err = s.read("minimum.json", &minimum, 1<<20); err != nil || minimum.Revoked == nil || now.Before(minimum.At) || len(minimum.Revoked) > 4096 {
		return false, errUnsafe
	}
	for key, revoked := range minimum.Revoked {
		if !validKey(key) || !revoked {
			return false, errUnsafe
		}
		state.Revoked[key] = true
	}
	state.At = now
	if revoked {
		state.Revoked[key] = true
	}
	if len(state.Revoked) > 4096 {
		return false, errUnsafe
	}
	if err = s.write("minimum.json", state); err != nil {
		return false, err
	}
	if err = s.write("floor.json", state); err != nil {
		return false, err
	}
	return state.Revoked[key], nil
}
