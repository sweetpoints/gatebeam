package secrets

import (
	"bytes"
	"filippo.io/age"
	"os"
	"path/filepath"
	"testing"
)

func TestRoleCiphertextWorksAcrossAuthorizedReplicas(t *testing.T) {
	type pair struct {
		a, b         *Store
		pathA, pathB string
		recipients   []string
	}
	all := map[string]pair{}
	for _, role := range []string{"api", "provider", "notification", "ca", "leaf"} {
		dir := t.TempDir()
		a, _ := age.GenerateX25519Identity()
		b, _ := age.GenerateX25519Identity()
		pa, pb := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		if err := os.WriteFile(pa, []byte(a.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pb, []byte(b.String()), 0600); err != nil {
			t.Fatal(err)
		}
		recipients := []string{a.Recipient().String(), b.Recipient().String()}
		sa, err := NewRoleStore(pa, recipients)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := NewRoleStore(pb, recipients)
		if err != nil {
			t.Fatal(err)
		}
		all[role] = pair{sa, sb, pa, pb, recipients}
	}
	for role, pair := range all {
		label := role + "/owned-test-payload"
		cipher, err := pair.a.Seal(label, []byte("role-owned-test-secret"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) {
			t.Fatal("role store invented an encryption format")
		}
		if value, err := pair.b.Open(label, cipher); err != nil || string(value) != "role-owned-test-secret" {
			t.Fatalf("authorized %s replica cannot open peer data: %v", role, err)
		}
		for other, keys := range all {
			if other != role {
				if _, err := keys.a.Open(label, cipher); err == nil {
					t.Fatalf("%s decrypted %s data", other, role)
				}
			}
		}
		legacy, err := New(pair.pathA)
		if err != nil {
			t.Fatal(err)
		}
		old, err := legacy.Seal(label, []byte("historical-owner-only"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pair.b.Open(label, old); err == nil {
			t.Fatal("new recipient silently opened old ciphertext without owner rewrap")
		}
		plain, err := pair.a.Open(label, old)
		if err != nil {
			t.Fatal(err)
		}
		rewrapped, err := pair.a.Seal(label, plain)
		clear(plain)
		if err != nil {
			t.Fatal(err)
		}
		if value, err := pair.b.Open(label, rewrapped); err != nil || string(value) != "historical-owner-only" {
			t.Fatal("owner-authorized standard age rewrap failed", err)
		}
		sealer, err := NewRecipients(pair.recipients)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := sealer.Seal(label, []byte("public-seal-only"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pair.b.Open(label, sealed); err != nil {
			t.Fatal("seal-only role recipient set omitted a replica", err)
		}
	}
	api := all["api"]
	if _, err := NewRoleStore(api.pathA, all["ca"].recipients); err == nil {
		t.Fatal("own identity omitted from role authorization set")
	}
	if _, err := NewRecipients([]string{"not-an-age-recipient"}); err == nil {
		t.Fatal("invalid recipient accepted")
	}
}
