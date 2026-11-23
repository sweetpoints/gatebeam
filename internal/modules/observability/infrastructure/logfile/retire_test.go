package logfile

import (
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"os"
	"path/filepath"
	"testing"
)

const retiredName = "access.20261107T120000.000000000.log"

func TestMissingRetiredSourceFinishesMarkerCleanup(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	marker := filepath.Join(dir, retiredName+".closed")
	if e = os.WriteFile(marker, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e = s.RemoveRetired(domain.Segment{Path: retiredName, Closed: true}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(marker); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("crash recovery leaked closed marker", e)
	}
}

func TestMissingRetirementRequiresSyncEvenAfterMarkerWasRemoved(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = os.WriteFile(filepath.Join(dir, retiredName+".closed"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	failure := errors.New("injected directory sync failure")
	seg := domain.Segment{Path: retiredName, Closed: true}
	calls := 0
	if e = s.removeRetired(seg, func() error { calls++; return failure }); !errors.Is(e, failure) {
		t.Fatal("sync failure reported success", e)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	if e = s.removeRetired(seg, func() error { calls++; return nil }); e != nil || calls != 2 {
		t.Fatal("marker absence bypassed retry sync", e, calls)
	}
}
func TestRetirementRecoveryPreservesReplacementAndMarker(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	source := filepath.Join(dir, retiredName)
	marker := source + ".closed"
	if e = os.WriteFile(source, []byte("replacement\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(marker, nil, 0600); e != nil {
		t.Fatal(e)
	}
	synced := false
	if e = s.removeRetired(domain.Segment{Path: retiredName, ID: "old-inode", Fingerprint: "old", Closed: true}, func() error { synced = true; return nil }); e != nil || !synced {
		t.Fatal(e)
	}
	if data, e := os.ReadFile(source); e != nil || string(data) != "replacement\n" {
		t.Fatal("replacement removed", e)
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("replacement marker removed", e)
	}
	if e = s.finishMissingRetirement(retiredName, func() error { return nil }); !errors.Is(e, domain.ErrSourceChanged) {
		t.Fatal("missing branch accepted replacement", e)
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("replacement marker removed by missing branch", e)
	}
}
