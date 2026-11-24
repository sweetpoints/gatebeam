//go:build integration

package pkicrypto

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"gatebeam-ca/internal/modules/pki/application"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCRLOfflineRootRenewalAndRevokedIssuerPublication(t *testing.T) {
	executable := os.Getenv("GATEBEAM_TEST_OPENSSL")
	if executable == "" {
		t.Fatal("GATEBEAM_TEST_OPENSSL required")
	}
	dir := t.TempDir()
	offline, online := filepath.Join(dir, "offline"), filepath.Join(dir, "online")
	if e := (Bootstrapper{}).Generate(context.Background(), application.BootstrapCommand{RootDirectory: offline, OnlineDirectory: online, RootName: "offline CRL root", IntermediateName: "online CRL issuer"}); e != nil {
		t.Fatal(e)
	}
	cfg := Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")}
	issuer, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	configuration := `[ca]
default_ca=root
[root]
database=index.txt
crlnumber=crlnumber
certificate=root.pem
private_key=root-key.pem
default_md=sha384
default_crl_days=30
`
	for name, data := range map[string]string{"openssl.cnf": configuration, "index.txt": "", "crlnumber": "02\n"} {
		if e = os.WriteFile(filepath.Join(offline, name), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Dir = offline
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("offline OpenSSL: %v %s", e, b)
		}
	}
	// Renew only the public delegated certificate offline; the distinct
	// encrypted online key can be retained without exporting it to the root host.
	run("x509", "-in", filepath.Join(online, "root-ocsp.pem"), "-pubkey", "-noout", "-out", "delegate-public.pem")
	if e = os.WriteFile(filepath.Join(offline, "delegate.cnf"), []byte("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,OCSPSigning\n"), 0600); e != nil {
		t.Fatal(e)
	}
	run("x509", "-new", "-force_pubkey", "delegate-public.pem", "-subj", "/CN=Root OCSP delegate", "-CA", "root.pem", "-CAkey", "root-key.pem", "-set_serial", "0x1234", "-days", "1", "-extfile", "delegate.cnf", "-out", "delegate-renewed.pem")
	renewed, e := LoadRootStatus(issuer, filepath.Join(offline, "delegate-renewed.pem"), filepath.Join(online, "root-ocsp.age"), filepath.Join(online, "identity.agekey"), filepath.Join(online, "root.crl.der"))
	if e != nil || renewed.Credential.SerialNumber.Int64() != 0x1234 {
		t.Fatal("offline delegated credential renewal failed", e)
	}
	run("ca", "-config", "openssl.cnf", "-valid", cfg.CertificateFile)
	run("ca", "-config", "openssl.cnf", "-gencrl", "-out", "renewed.pem")
	read := func() []byte {
		b, e := os.ReadFile(filepath.Join(offline, "renewed.pem"))
		if e != nil {
			t.Fatal(e)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatal("missing CRL")
		}
		return block.Bytes
	}
	public := filepath.Join(online, "renewed.der")
	if e = os.WriteFile(public, read(), 0600); e != nil {
		t.Fatal(e)
	}
	reader := RootCRLReader{Root: issuer.Chain[0], Path: public}
	b, e := reader.ReadRootCRL(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	list, e := x509.ParseRevocationList(b)
	if e != nil || list.Number.Int64() != 2 {
		t.Fatal("renewal lost root CRL version", e)
	}
	if e = reader.CheckIssuer(context.Background(), issuer.Certificate); e != nil {
		t.Fatal(e)
	}
	run("ca", "-config", "openssl.cnf", "-revoke", cfg.CertificateFile, "-crl_reason", "keyCompromise")
	run("ca", "-config", "openssl.cnf", "-gencrl", "-out", "renewed.pem")
	if e = os.WriteFile(public, read(), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = reader.ReadRootCRL(context.Background()); e != nil {
		t.Fatal("revoked issuer CRL must remain publishable", e)
	}
	if e = reader.CheckIssuer(context.Background(), issuer.Certificate); e == nil {
		t.Fatal("revoked intermediate accepted at CA startup")
	}
	if b, e = os.ReadFile(filepath.Join(offline, "crlnumber")); e != nil || strings.TrimSpace(string(b)) != "04" {
		t.Fatal("offline CRL number not monotonic", e)
	}
}
