package pkicrypto

import (
	"bytes"
	"context"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/platform/secrets"
	"os"
	"path/filepath"
	"testing"
)

func TestOnlineSignerRewrapRetainsOwnerAndNeverChangesOfflineRoot(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	online := filepath.Join(dir, "online")
	offline := filepath.Join(dir, "offline")
	if e = (Bootstrapper{}).Generate(t.Context(), application.BootstrapCommand{RootDirectory: offline, OnlineDirectory: online, RootName: "rewrap root", IntermediateName: "rewrap intermediate", StatusOrigin: "http://status.owned.test"}); e != nil {
		t.Fatal(e)
	}
	cfg := Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")}
	pathB := filepath.Join(dir, "identity-b")
	if e = secrets.EnsureIdentity(pathB); e != nil {
		t.Fatal(e)
	}
	a, e := secrets.New(cfg.IdentityFile)
	if e != nil {
		t.Fatal(e)
	}
	b, e := secrets.New(pathB)
	if e != nil {
		t.Fatal(e)
	}
	recipients := []string{a.Recipient(), b.Recipient()}
	rootKey, e := os.ReadFile(filepath.Join(offline, "root-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	paths := []string{cfg.SignerFile, filepath.Join(online, "root-ocsp.age")}
	labels := []string{"pki-online-issuer", "pki-root-ocsp"}
	plaintext := make([][]byte, 2)
	for i, path := range paths {
		cipher, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		plaintext[i], e = a.Open(labels[i], cipher)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = b.Open(labels[i], cipher); e == nil {
			t.Fatal("new CA B already held original key")
		}
	}
	if e = RewrapOnlineSigners(t.Context(), cfg, paths[1], recipients); e != nil {
		t.Fatal(e)
	}
	for i, path := range paths {
		cipher, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		for _, holder := range []*secrets.Store{a, b} {
			plain, e := holder.Open(labels[i], cipher)
			if e != nil || !bytes.Equal(plain, plaintext[i]) {
				t.Fatal("rewrap changed logical key or stranded owner", e)
			}
			clear(plain)
		}
		clear(plaintext[i])
	}
	after, e := os.ReadFile(filepath.Join(offline, "root-key.pem"))
	if e != nil || !bytes.Equal(after, rootKey) {
		t.Fatal("offline root private key changed", e)
	}
	clear(rootKey)
	clear(after)
	before, e := os.ReadFile(cfg.SignerFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = RewrapOnlineSigners(context.Background(), cfg, paths[1], []string{b.Recipient()}); e == nil {
		t.Fatal("original holder exclusion accepted")
	}
	after, e = os.ReadFile(cfg.SignerFile)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid recipient set changed files", e)
	}
}
