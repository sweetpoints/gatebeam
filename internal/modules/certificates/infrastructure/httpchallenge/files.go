// Package httpchallenge maintains only files owned by the standard HTTP-01
// challenge journal. No certificate keys or enrollment protocol live here.
package httpchallenge

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

type Files struct{ root, dir, state string }

func safeDir(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return app.ErrChallenge
	}
	if clean != string(filepath.Separator) {
		if e := safeDir(filepath.Dir(clean)); e != nil {
			return e
		}
	}
	if e := os.Mkdir(clean, 0755); e != nil && !os.IsExist(e) {
		return e
	}
	info, e := os.Lstat(clean)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return app.ErrChallenge
	}
	return nil
}
func New(root string) (*Files, error) { return NewScoped(root, ".gatebeam-http01") }

// NewScoped keeps local role tokens separate from the shared business journal.
func NewScoped(root, scope string) (*Files, error) {
	if scope != ".gatebeam-http01" && scope != ".gatebeam-http01-private-role" {
		return nil, app.ErrChallenge
	}
	if root == "" || !filepath.IsAbs(root) {
		return nil, app.ErrChallenge
	}
	f := &Files{root: root, dir: filepath.Join(root, ".well-known", "acme-challenge"), state: filepath.Join(root, scope)}
	if e := safeDir(f.dir); e != nil {
		return nil, e
	}
	if e := safeDir(f.state); e != nil {
		return nil, e
	}
	if e := os.Chmod(f.state, 0700); e != nil {
		return nil, e
	}
	return f, nil
}
func replace(path string, body []byte, mode os.FileMode) error {
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return app.ErrChallenge
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".http01-")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if e = tmp.Chmod(mode); e == nil {
		_, e = tmp.Write(body)
	}
	if e == nil {
		e = tmp.Sync()
	}
	e = errors.Join(e, tmp.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (f *Files) Reconcile(ctx context.Context, pending []app.HTTPChallenge) error {
	if len(pending) > 128 {
		return app.ErrChallenge
	}
	fd, e := syscall.Open(filepath.Join(f.state, "lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return e
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	current := map[string]app.HTTPChallenge{}
	for _, c := range pending {
		if !tokenPattern.MatchString(c.Token) || len(c.KeyAuthorization) > 513 {
			return app.ErrChallenge
		}
		if _, ok := current[c.Token]; ok {
			return app.ErrChallenge
		}
		current[c.Token] = c
	}
	path := filepath.Join(f.state, "owned.json")
	previous := map[string]app.HTTPChallenge{}
	fd, e = syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e == nil {
		file := os.NewFile(uintptr(fd), path)
		info, statErr := file.Stat()
		if statErr != nil || info.Size() > 131072 {
			file.Close()
			return app.ErrChallenge
		}
		e = json.NewDecoder(file).Decode(&previous)
		file.Close()
		if e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	// Record the union first. A crash after writing a token must not orphan an
	// untracked public challenge file on the next process start.
	union := map[string]app.HTTPChallenge{}
	for k, v := range previous {
		union[k] = v
	}
	for k, v := range current {
		union[k] = v
	}
	body, _ := json.Marshal(union)
	if e = replace(path, body, 0600); e != nil {
		return e
	}
	for token, c := range current {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = replace(filepath.Join(f.dir, token), []byte(c.KeyAuthorization), 0644); e != nil {
			return e
		}
	}
	for token, c := range previous {
		if _, ok := current[token]; ok {
			continue
		}
		if !tokenPattern.MatchString(token) {
			return app.ErrChallenge
		}
		path := filepath.Join(f.dir, token)
		info, e := os.Lstat(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return app.ErrChallenge
		}
		got, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if string(got) != c.KeyAuthorization {
			return app.ErrChallenge
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	dir, e := os.Open(f.dir)
	if e != nil {
		return e
	}
	e = dir.Sync()
	e = errors.Join(e, dir.Close())
	if e != nil {
		return e
	}
	body, _ = json.Marshal(current)
	return replace(path, body, 0600)
}
