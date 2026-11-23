package bootstrap

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementMaintenancePersistsOnlyProtectedTargets(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "management.json")
	initial := ManagementState{Revision: 1, Unavailable: []string{}}
	body, _ := json.Marshal(initial)
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	a, b := netip.MustParseAddrPort("10.0.0.1:8444"), netip.MustParseAddrPort("10.0.0.2:8444")
	saved, e := UpdateManagementState(path, a, b, a.String(), true)
	if e != nil || saved.Revision != 2 || len(saved.Unavailable) != 1 {
		t.Fatal(saved, e)
	}
	retry, e := UpdateManagementState(path, a, b, a.String(), true)
	if e != nil || retry.Digest() != saved.Digest() {
		t.Fatal("retry changed maintenance authority", retry, e)
	}
	reopened, e := ReadManagementState(path, b, a)
	if e != nil || reopened.Digest() != saved.Digest() {
		t.Fatal("restart lost excluded API", reopened, e)
	}
	if _, e = UpdateManagementState(path, a, b, "10.0.0.99:8444", true); e == nil {
		t.Fatal("foreign management target accepted")
	}
	enabled, e := UpdateManagementState(path, a, b, a.String(), false)
	if e != nil || enabled.Revision != 3 || enabled.Digest() == initial.Digest() {
		t.Fatal("return to prior state lost distinct revision", enabled, e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadManagementState(path, a, b); e == nil {
		t.Fatal("missing persisted maintenance silently reopened API")
	}
}

func TestInitialManagementStateNeverReopensExcludedPeer(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "management.json")
	a, b := netip.MustParseAddrPort("10.0.0.1:9443"), netip.MustParseAddrPort("10.0.0.2:9443")
	if _, e = InitializeManagementState(path, a, b); e != nil {
		t.Fatal(e)
	}
	if _, e = UpdateManagementState(path, a, b, b.String(), true); e != nil {
		t.Fatal(e)
	}
	state, e := InitializeManagementState(path, a, b)
	if e != nil || state.Revision != 2 || len(state.Unavailable) != 1 || state.Unavailable[0] != b.String() {
		t.Fatal("initialization reset prior maintenance authority", state, e)
	}
}
