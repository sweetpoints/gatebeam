package secrets

import (
	"bytes"
	"filippo.io/age"
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity")
	if err = os.WriteFile(path, []byte(key.String()), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestAgeRoundTripAndLabelBinding(t *testing.T) {
	s := newStore(t)
	c, err := s.Seal("totp:user-a", []byte("test-only"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(c, []byte("age-encryption.org/v1\n")) {
		t.Fatal("not age format")
	}
	p, err := s.Open("totp:user-a", c)
	if err != nil || string(p) != "test-only" {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err = s.Open("totp:user-b", c); err == nil {
		t.Fatal("accepted wrong label")
	}
	c[len(c)-1] ^= 1
	if _, err = s.Open("totp:user-a", c); err == nil {
		t.Fatal("accepted tampering")
	}
}
func TestRejectWrongIdentityAndMalformed(t *testing.T) {
	s := newStore(t)
	c, err := s.Seal("a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newStore(t).Open("a", c); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = s.Open("a", []byte("secret-body")); err == nil {
		t.Fatal("malformed accepted")
	}
	if _, err = New(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err = s.Seal("", nil); err == nil {
		t.Fatal("empty label accepted")
	}
}
