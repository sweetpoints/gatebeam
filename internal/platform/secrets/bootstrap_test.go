package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapIdentityCreatesOnceAndRejectsInvalid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "identity")
	if e := EnsureIdentity(p); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatal("identity permissions")
	}
	if e = EnsureIdentity(p); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(before) {
		t.Fatal("identity overwritten")
	}
	if e = os.WriteFile(p, []byte("invalid-private-data"), 0600); e != nil {
		t.Fatal(e)
	}
	e = EnsureIdentity(p)
	if e == nil || e.Error() == "invalid-private-data" {
		t.Fatal("invalid identity accepted or leaked")
	}
	after, _ = os.ReadFile(p)
	if string(after) != "invalid-private-data" {
		t.Fatal("invalid file overwritten")
	}
}
