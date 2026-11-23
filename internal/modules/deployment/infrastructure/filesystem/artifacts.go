package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var digestID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func artifactDigest(files map[string][]byte) (string, error) {
	if len(files) == 0 || len(files) > 10000 {
		return "", errors.New("invalid artifact file count")
	}
	keys := []string{}
	size := 0
	for k, v := range files {
		if filepath.IsAbs(k) || filepath.Clean(k) != k || k == "." || strings.HasPrefix(k, "../") || strings.Contains(k, "\\") {
			return "", errors.New("invalid artifact path")
		}
		keys = append(keys, k)
		size += len(v)
	}
	if size > 64<<20 {
		return "", errors.New("artifact too large")
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s:%d:", len(k), k, len(files[k]))
		h.Write(files[k])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (s *Store) Stage(ctx context.Context, a edge.Artifact) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	digest, e := artifactDigest(a.Files)
	if e != nil {
		return "", e
	}
	if !digestID.MatchString(a.ID) || a.ID != a.Digest || digest != a.Digest {
		return "", errors.New("artifact digest mismatch")
	}
	parent := filepath.Join(s.root, "releases")
	final := filepath.Join(parent, a.ID)
	if info, e := os.Lstat(final); e == nil {
		if !info.IsDir() {
			return "", errors.New("artifact is not a directory")
		}
		for k, want := range a.Files {
			p := filepath.Join(final, k)
			info, e := os.Lstat(p)
			if e != nil || !info.Mode().IsRegular() {
				return "", errors.New("invalid existing artifact")
			}
			got, e := os.ReadFile(p)
			if e != nil || string(got) != string(want) {
				return "", errors.New("existing artifact corrupted")
			}
		}
		return final, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	tmp, e := os.MkdirTemp(parent, ".stage-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(tmp)
	dirs := map[string]bool{tmp: true}
	for k, data := range a.Files {
		if e = ctx.Err(); e != nil {
			return "", e
		}
		dir := filepath.Dir(filepath.Join(tmp, k))
		if e = os.MkdirAll(dir, 0700); e != nil {
			return "", e
		}
		for d := dir; strings.HasPrefix(d, tmp); d = filepath.Dir(d) {
			dirs[d] = true
			if d == tmp {
				break
			}
		}
		f, e := os.OpenFile(filepath.Join(tmp, k), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return "", e
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return "", e
		}
		if ce != nil {
			return "", ce
		}
	}
	keys := []string{}
	for d := range dirs {
		keys = append(keys, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, d := range keys {
		if e = syncDir(d); e != nil {
			return "", e
		}
	}
	if e = os.Rename(tmp, final); e != nil {
		return "", e
	}
	if e = syncDir(parent); e != nil {
		return "", e
	}
	return final, nil
}
func (s *Store) Switch(ctx context.Context, id string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !digestID.MatchString(id) {
		return errors.New("invalid artifact identity")
	}
	info, e := os.Lstat(filepath.Join(s.root, "releases", id))
	if e != nil || !info.IsDir() {
		return errors.New("artifact missing")
	}
	f, e := os.CreateTemp(s.root, ".current-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	f.Close()
	os.Remove(tmp)
	defer os.Remove(tmp)
	if e = os.Symlink(filepath.Join("releases", id), tmp); e != nil {
		return e
	}
	if e = os.Rename(tmp, filepath.Join(s.root, "current")); e != nil {
		return e
	}
	return syncDir(s.root)
}
