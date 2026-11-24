package secrets

import (
	"path/filepath"
	"testing"
)

func TestPublicRecipientCannotOpenAndCAIdentityDecrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.key")
	if e := EnsureIdentity(path); e != nil {
		t.Fatal(e)
	}
	ca, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	public, e := NewRecipient(ca.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	sealed, e := public.Seal("pki/eab/owned", []byte("owned-test-secret"))
	if e != nil {
		t.Fatal(e)
	}
	plain, e := ca.Open("pki/eab/owned", sealed)
	if e != nil || string(plain) != "owned-test-secret" {
		t.Fatal("recipient interoperability", e)
	}
	if _, e = ca.Open("pki/eab/wrong", sealed); e == nil {
		t.Fatal("label not bound")
	}
	other := filepath.Join(t.TempDir(), "api.key")
	_ = EnsureIdentity(other)
	api, _ := New(other)
	if _, e = api.Open("pki/eab/owned", sealed); e == nil {
		t.Fatal("API identity decrypted CA secret")
	}
}
