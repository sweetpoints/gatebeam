package pkicrypto

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"gatebeam-ca/internal/modules/pki/application"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineBootstrapSeparatesRootAndOnlineMaterialWithoutOverwrite(t *testing.T) {
	base := t.TempDir()
	cmd := application.BootstrapCommand{RootDirectory: filepath.Join(base, "offline"), OnlineDirectory: filepath.Join(base, "online"), RootName: "owned offline root", IntermediateName: "owned online CA"}
	if e := (Bootstrapper{}).Generate(context.Background(), cmd); e != nil {
		t.Fatal(e)
	}
	cfg := Config{CertificateFile: filepath.Join(cmd.OnlineDirectory, "issuer.pem"), RootFile: filepath.Join(cmd.OnlineDirectory, "root.pem"), SignerFile: filepath.Join(cmd.OnlineDirectory, "issuer.age"), IdentityFile: filepath.Join(cmd.OnlineDirectory, "identity.agekey")}
	iss, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if !iss.Certificate.IsCA || !iss.Certificate.MaxPathLenZero {
		t.Fatal("invalid intermediate")
	}
	b, e := os.ReadFile(filepath.Join(cmd.RootDirectory, "root-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("not PKCS8 PEM")
	}
	if _, e = x509.ParsePKCS8PrivateKey(block.Bytes); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{cmd.RootDirectory, cmd.OnlineDirectory} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			info, e := entry.Info()
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("unsafe file mode")
			}
		}
	}
	if _, e = os.Stat(filepath.Join(cmd.OnlineDirectory, "root-key.pem")); !os.IsNotExist(e) {
		t.Fatal("root secret copied online")
	}
	if e = (Bootstrapper{}).Generate(context.Background(), cmd); e == nil {
		t.Fatal("overwrote existing ceremony")
	}
	after, e := os.ReadFile(filepath.Join(cmd.RootDirectory, "root-key.pem"))
	if e != nil || string(after) != string(b) {
		t.Fatal("existing root altered")
	}
}
func TestOfflineBootstrapRejectsOverlappingOrExistingDirectories(t *testing.T) {
	for _, nested := range []bool{false, true} {
		base := t.TempDir()
		root := filepath.Join(base, "offline")
		online := root
		if nested {
			online = filepath.Join(root, "online")
		}
		if e := (Bootstrapper{}).Generate(context.Background(), application.BootstrapCommand{RootDirectory: root, OnlineDirectory: online, RootName: "root", IntermediateName: "intermediate"}); e == nil {
			t.Fatal("overlap accepted")
		}
		if _, e := os.Stat(root); !os.IsNotExist(e) {
			t.Fatal("wrote files before validating paths")
		}
	}
}

func TestBootstrapPublishesOnlyPublicAgeRecipientForAPI(t *testing.T) {
	base := t.TempDir()
	cmd := application.BootstrapCommand{RootDirectory: filepath.Join(base, "offline"), OnlineDirectory: filepath.Join(base, "online"), RootName: "owned root", IntermediateName: "owned issuer"}
	if e := (Bootstrapper{}).Generate(context.Background(), cmd); e != nil {
		t.Fatal(e)
	}
	public, e := os.ReadFile(filepath.Join(cmd.OnlineDirectory, "recipient.txt"))
	if e != nil || len(public) < 10 || string(public[:4]) != "age1" {
		t.Fatal("public age recipient missing")
	}
}
