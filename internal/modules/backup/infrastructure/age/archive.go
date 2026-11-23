// Package age writes standard age-encrypted tar data without plaintext staging.
package age

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	agefmt "filippo.io/age"
	"fmt"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/modules/backup/domain"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func Digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func ReadRegular(path string, max int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil, domain.ErrInvalid
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, domain.ErrInvalid
	}
	defer f.Close()
	now, e := f.Stat()
	if e != nil || !os.SameFile(st, now) {
		return nil, domain.ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, domain.ErrInvalid
	}
	return b, nil
}
func Encrypt(w io.Writer, recipient string, body []byte) error {
	r, e := agefmt.ParseX25519Recipient(recipient)
	if e != nil {
		return domain.ErrInvalid
	}
	enc, e := agefmt.Encrypt(w, r)
	if e != nil {
		return domain.ErrInvalid
	}
	if _, e = enc.Write(body); e != nil {
		return e
	}
	return enc.Close()
}
func Decrypt(body []byte, identity string) ([]byte, error) {
	k, e := ReadRegular(identity, 4096)
	if e != nil {
		return nil, e
	}
	ids, e := agefmt.ParseIdentities(bytes.NewReader(k))
	if e != nil || len(ids) != 1 {
		return nil, domain.ErrInvalid
	}
	r, e := agefmt.Decrypt(bytes.NewReader(body), ids...)
	if e != nil {
		return nil, domain.ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(r, domain.MaxArchive+1))
	if e != nil || len(b) > domain.MaxArchive {
		return nil, domain.ErrInvalid
	}
	return b, nil
}

// Write accepts a complete bounded consistent logical snapshot and streams tar
// directly into age. No tar/plaintext file is created on disk.
func Write(ctx context.Context, dir, recipient string, m application.Manifest, files map[string][]byte) (application.Artifact, error) {
	if e := ctx.Err(); e != nil {
		return application.Artifact{}, e
	}
	m.Recipient = recipient
	m.Files = nil
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := files[n]
		m.Files = append(m.Files, domain.File{Name: n, Bytes: int64(len(b)), SHA256: Digest(b)})
	}
	m.ID = Digest([]byte(fmt.Sprintf("%s/%s/%d/%v", m.Snapshot, m.Epoch, m.Created.UnixNano(), m.Files)))
	if e := m.Validate(); e != nil {
		return application.Artifact{}, e
	}
	r, e := agefmt.ParseX25519Recipient(recipient)
	if e != nil {
		return application.Artifact{}, domain.ErrInvalid
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return application.Artifact{}, e
	}
	defer root.Close()
	name := m.ID + ".age"
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if e != nil {
		return application.Artifact{}, e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			root.Remove(name)
		}
	}()
	h := sha256.New()
	enc, e := agefmt.Encrypt(io.MultiWriter(f, h), r)
	if e != nil {
		return application.Artifact{}, e
	}
	tw := tar.NewWriter(enc)
	for _, n := range names {
		if e = ctx.Err(); e != nil {
			return application.Artifact{}, e
		}
		b := files[n]
		if e = tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(b)), Mode: 0600, Typeflag: tar.TypeReg}); e != nil {
			return application.Artifact{}, e
		}
		if _, e = tw.Write(b); e != nil {
			return application.Artifact{}, e
		}
	}
	b, _ := json.Marshal(m)
	if e = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(b)), Mode: 0600, Typeflag: tar.TypeReg}); e != nil {
		return application.Artifact{}, e
	}
	if _, e = tw.Write(b); e != nil {
		return application.Artifact{}, e
	}
	if e = tw.Close(); e != nil {
		return application.Artifact{}, e
	}
	if e = enc.Close(); e != nil {
		return application.Artifact{}, e
	}
	if e = f.Chmod(0640); e != nil {
		return application.Artifact{}, e
	}
	if e = f.Sync(); e != nil {
		return application.Artifact{}, e
	}
	st, e := f.Stat()
	if e != nil {
		return application.Artifact{}, e
	}
	if e = f.Close(); e != nil {
		return application.Artifact{}, e
	}
	a := application.Artifact{Manifest: m, Path: filepath.Join(dir, name), SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: st.Size()}
	meta, _ := json.Marshal(a)
	if e = exclusive(root, m.ID+".json", meta); e != nil {
		return application.Artifact{}, e
	}
	// Publish only a complete immutable pair. The worker follows this bounded
	// pointer instead of scanning a directory whose retention can span a year.
	pointer := m.ID + ".current"
	if e = exclusive(root, pointer, []byte(m.ID)); e != nil {
		return application.Artifact{}, e
	}
	defer root.Remove(pointer)
	if e = root.Rename(pointer, "current"); e != nil {
		return application.Artifact{}, e
	}
	ok = true
	return a, nil
}
func exclusive(root *os.Root, name string, b []byte) error {
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Chmod(0640); e != nil {
		return e
	}
	return f.Sync()
}

type Decoder struct{}

func (Decoder) Decode(ctx context.Context, source, identity string) (application.Archive, string, error) {
	fail := func() (application.Archive, string, error) { return application.Archive{}, "", domain.ErrInvalid }
	if ctx.Err() != nil {
		return fail()
	}
	cipher, e := ReadRegular(source, domain.MaxArchive)
	if e != nil {
		return fail()
	}
	body, e := Decrypt(cipher, identity)
	if e != nil {
		return fail()
	}
	tr := tar.NewReader(bytes.NewReader(body))
	files := map[string][]byte{}
	var m application.Manifest
	manifest := false
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || manifest || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > domain.MaxFile || len(files) > 128 {
			return fail()
		}
		total += h.Size
		if total > domain.MaxArchive {
			return fail()
		}
		b, e := io.ReadAll(tr)
		if e != nil {
			return fail()
		}
		if h.Name == "manifest.json" {
			if json.Unmarshal(b, &m) != nil {
				return fail()
			}
			manifest = true
			continue
		}
		if !domain.ValidName(h.Name) || files[h.Name] != nil {
			return fail()
		}
		files[h.Name] = b
	}
	if !manifest || m.Validate() != nil || len(m.Files) != len(files) {
		return fail()
	}
	for _, f := range m.Files {
		b, ok := files[f.Name]
		if !ok || int64(len(b)) != f.Bytes || Digest(b) != f.SHA256 {
			return fail()
		}
	}
	return application.Archive{Manifest: m, Files: files}, Digest(cipher), nil
}

type Source struct{ Directory string }

func (s Source) Latest(ctx context.Context, maxAge time.Duration) (application.Artifact, error) {
	if e := ctx.Err(); e != nil {
		return application.Artifact{}, e
	}
	// Constant-size current/manifest reads keep the upload and catalog-retention
	// path available regardless of how many historical local copies remain.
	pointer, e := ReadRegular(filepath.Join(s.Directory, "current"), 64)
	if e != nil {
		return application.Artifact{}, e
	}
	id := strings.TrimSpace(string(pointer))
	if !domain.ValidDigest(id) {
		return application.Artifact{}, domain.ErrInvalid
	}
	metadata, e := ReadRegular(filepath.Join(s.Directory, id+".json"), 65536)
	if e != nil {
		return application.Artifact{}, e
	}
	var a application.Artifact
	if json.Unmarshal(metadata, &a) != nil || a.Manifest.Validate() != nil || a.Manifest.ID != id || time.Since(a.Manifest.Created) > maxAge {
		return application.Artifact{}, domain.ErrInvalid
	}
	a.Path = filepath.Join(s.Directory, id+".age")
	b, e := ReadRegular(a.Path, domain.MaxArchive)
	if e != nil || int64(len(b)) != a.Bytes || Digest(b) != a.SHA256 {
		return application.Artifact{}, domain.ErrInvalid
	}
	return a, nil
}

func (s Source) Cleanup(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !domain.ValidDigest(id) {
		return domain.ErrInvalid
	}
	r, e := os.OpenRoot(s.Directory)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, ext := range []string{".age", ".json"} {
		st, e := r.Lstat(id + ext)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || !st.Mode().IsRegular() {
			return domain.ErrInvalid
		}
		if e = r.Remove(id + ext); e != nil {
			return e
		}
	}
	return nil
}
