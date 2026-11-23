package logfile_test

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"os"
	"path/filepath"
	"testing"
)

func TestControlledNamesSymlinksPartialAndClosedTail(t *testing.T) {
	dir := t.TempDir()
	s, e := logfile.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	if _, e = s.Read(ctx, domain.Segment{Path: "../outside"}, domain.Cursor{}); !errors.Is(e, domain.ErrInvalid) {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("private"), 0600)
	os.Symlink(outside, filepath.Join(dir, "access.log"))
	if _, e = s.Discover(ctx); e == nil {
		t.Fatal("symlink admitted")
	}
	os.Remove(filepath.Join(dir, "access.log"))
	name := "access.20261107T000000.000000001.log"
	os.WriteFile(filepath.Join(dir, name), []byte("bad\npartial"), 0600)
	segs, e := s.Discover(ctx)
	if e != nil || len(segs) != 1 {
		t.Fatal(segs, e)
	}
	r, e := s.Read(ctx, segs[0], domain.Cursor{})
	if e != nil || r.End != 4 || r.Invalid != 1 {
		t.Fatal(r, e)
	}
	os.WriteFile(filepath.Join(dir, name+".closed"), nil, 0600)
	segs, e = s.Discover(ctx)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.Read(ctx, segs[0], domain.Cursor{Offset: 4, Fingerprint: segs[0].Fingerprint})
	if e != nil || r.End != 11 || r.Invalid != 1 {
		t.Fatal(r, e)
	}
	s.MaxFiles = 1
	if _, e = s.Discover(ctx); !errors.Is(e, domain.ErrCapacity) {
		t.Fatal("file budget ignored", e)
	}
}

func TestRetirementNeverDeletesActiveOrChangedSource(t *testing.T) {
	dir := t.TempDir()
	source, e := logfile.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	name := "access.20261107T120000.000000000.log"
	if e = os.WriteFile(filepath.Join(dir, name), []byte("first\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, name+".closed"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	segments, e := source.Discover(t.Context())
	if e != nil || len(segments) != 1 {
		t.Fatal(e)
	}
	seg := segments[0]
	bad := seg
	bad.Path = "access.log"
	if source.RemoveRetired(bad) == nil {
		t.Fatal("active removal allowed")
	}
	bad = seg
	bad.Size++
	if source.RemoveRetired(bad) == nil {
		t.Fatal("changed size accepted")
	}
	if e = source.RemoveRetired(seg); e != nil {
		t.Fatal(e)
	}
	if e = source.RemoveRetired(seg); e != nil {
		t.Fatal("crash retry", e)
	}
	if _, e = os.Stat(filepath.Join(dir, name)); !os.IsNotExist(e) {
		t.Fatal("closed source not removed")
	}
}
