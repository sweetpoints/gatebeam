package pkicrypto

import (
	"context"
	"gatebeam/internal/modules/pki/application"
	"gatebeam/internal/platform/secrets"
	"os"
	"path/filepath"
	"testing"
)

func TestStandardOfflineMaterialImportAndRestart(t *testing.T) {
	base := t.TempDir()
	online := filepath.Join(base, "old")
	if err := (Bootstrapper{}).Generate(t.Context(), application.BootstrapCommand{RootDirectory: filepath.Join(base, "offline"), OnlineDirectory: online, RootName: "existing root", IntermediateName: "offline signed intermediate"}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(base, "standard")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := secrets.New(filepath.Join(online, "identity.agekey"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"issuer.pem", "root.pem", "root-ocsp.pem", "root.crl.der"} {
		b, err := os.ReadFile(filepath.Join(online, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(input, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, label := range map[string]string{"issuer": "pki-online-issuer", "root-ocsp": "pki-root-ocsp"} {
		b, err := os.ReadFile(filepath.Join(online, name+".age"))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := store.Open(label, b)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(input, name+"-key.pem"), plain, 0600); err != nil {
			t.Fatal(err)
		}
		clear(plain)
	}
	output := filepath.Join(base, "imported")
	if err := (Importer{}).Import(context.Background(), application.ImportCommand{SourceDirectory: input, OnlineDirectory: output}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{CertificateFile: filepath.Join(output, "issuer.pem"), RootFile: filepath.Join(output, "root.pem"), SignerFile: filepath.Join(output, "issuer.age"), IdentityFile: filepath.Join(output, "identity.agekey")}
	for range 2 {
		issuer, err := LoadIssuer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = LoadRootStatus(issuer, filepath.Join(output, "root-ocsp.pem"), filepath.Join(output, "root-ocsp.age"), cfg.IdentityFile, filepath.Join(output, "root.crl.der")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"root-key.pem", "issuer-key.pem", "root-ocsp-key.pem"} {
		if _, err = os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatal("plaintext key copied into online output")
		}
	}
	if err := (Importer{}).Import(t.Context(), application.ImportCommand{SourceDirectory: input, OnlineDirectory: output}); err == nil {
		t.Fatal("existing online epoch overwritten")
	}
	// A public certificate cannot disguise a different private key.
	wrong, err := os.ReadFile(filepath.Join(input, "issuer-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(input, "root-ocsp-key.pem"), wrong, 0600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(base, "rejected")
	if err := (Importer{}).Import(t.Context(), application.ImportCommand{SourceDirectory: input, OnlineDirectory: bad}); err == nil {
		t.Fatal("mismatched delegated key accepted")
	}
	if _, err = os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("failed import exposed output")
	}
}
