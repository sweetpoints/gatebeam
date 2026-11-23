// Package pkifixture contains owned, offline standard-tool ceremonies used by
// native acceptance. No production filesystem, root key or service is selected.
package pkifixture

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// RotateExistingRoot issues a new intermediate and distinct OCSP delegate with
// standard OpenSSL, revokes the old intermediate, advances the signed root CRL,
// and invokes the real ca-import CLI into a fresh encrypted online epoch.
func RotateExistingRoot(t *testing.T, base, online, statusOrigin string) {
	t.Helper()
	openssl, binary := os.Getenv("GATEBEAM_TEST_OPENSSL"), os.Getenv("GATEBEAM_CA_IMPORT_BINARY")
	if openssl == "" || binary == "" {
		t.Fatal("offline rotation requires explicit OpenSSL3 and fresh host Gatebeam binary")
	}
	offline := filepath.Join(base, "offline")
	old := filepath.Join(base, "old-online")
	source := filepath.Join(base, "standard-next")
	if err := os.Rename(online, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(offline, "newcerts"), 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) []byte {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	config := `[ca]
default_ca=root
[root]
database=index.txt
new_certs_dir=newcerts
serial=serial
crlnumber=crlnumber
certificate=root.pem
private_key=root-key.pem
default_md=sha384
default_days=365
default_crl_days=30
policy=policy
unique_subject=no
[policy]
commonName=supplied
[intermediate]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
[delegate]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,OCSPSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
`
	if statusOrigin != "" {
		config += "[intermediate_status]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nauthorityInfoAccess=OCSP;URI:" + statusOrigin + "/ocsp\ncrlDistributionPoints=URI:" + statusOrigin + "/crl/root.der\n"
	}
	for name, data := range map[string]string{"openssl.cnf": config, "index.txt": "", "serial": "1000\n", "crlnumber": "02\n"} {
		write(filepath.Join(offline, name), []byte(data))
	}
	run := func(executable string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.Dir = offline
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("owned offline standard command %s: %v %s", filepath.Base(executable), e, b)
		}
	}
	// Bootstrap created number 1 and two known signed credentials. This fixture
	// initializes their complete ledger once; operators preserve their real ledger.
	run(openssl, "ca", "-config", "openssl.cnf", "-valid", filepath.Join(old, "issuer.pem"))
	run(openssl, "ca", "-config", "openssl.cnf", "-valid", filepath.Join(old, "root-ocsp.pem"))
	for _, name := range []string{"issuer", "root-ocsp"} {
		key := filepath.Join(source, name+"-key.pem")
		csr := filepath.Join(source, name+".csr")
		run(openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", key)
		if e := os.Chmod(key, 0600); e != nil {
			t.Fatal(e)
		}
		run(openssl, "req", "-new", "-key", key, "-subj", "/CN=rotated "+name, "-out", csr)
		ext := "delegate"
		if name == "issuer" {
			ext = "intermediate"
			if statusOrigin != "" {
				ext = "intermediate_status"
			}
		}
		run(openssl, "ca", "-batch", "-notext", "-rand_serial", "-config", "openssl.cnf", "-extensions", ext, "-in", csr, "-out", filepath.Join(source, name+".pem"))
	}
	run(openssl, "ca", "-config", "openssl.cnf", "-revoke", filepath.Join(old, "issuer.pem"), "-crl_reason", "keyCompromise")
	run(openssl, "ca", "-config", "openssl.cnf", "-revoke", filepath.Join(old, "root-ocsp.pem"), "-crl_reason", "superseded")
	run(openssl, "ca", "-config", "openssl.cnf", "-gencrl", "-out", filepath.Join(source, "root.crl.pem"))
	run(openssl, "crl", "-in", filepath.Join(source, "root.crl.pem"), "-outform", "DER", "-out", filepath.Join(source, "root.crl.der"))
	write(filepath.Join(source, "root.pem"), read(filepath.Join(offline, "root.pem")))
	list, e := x509.ParseRevocationList(read(filepath.Join(source, "root.crl.der")))
	if e != nil || list.Number.Int64() != 2 || len(list.RevokedCertificateEntries) != 2 {
		t.Fatal("root CRL did not advance/revoke exact old credentials", e)
	}
	oldBlock, _ := pem.Decode(read(filepath.Join(old, "issuer.pem")))
	newBlock, _ := pem.Decode(read(filepath.Join(source, "issuer.pem")))
	if oldBlock == nil || newBlock == nil || bytes.Equal(oldBlock.Bytes, newBlock.Bytes) {
		t.Fatal("intermediate not rotated")
	}
	cfg := bootstrap.Config{Environment: "production", Mode: "ca-import", CAImportDirectory: source, CAOutputDirectory: online}
	b, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	configPath := filepath.Join(base, "import.json")
	write(configPath, b)
	run(binary, "--config", configPath)
	if !bytes.Equal(read(filepath.Join(online, "root.pem")), read(filepath.Join(offline, "root.pem"))) {
		t.Fatal("existing root changed during import")
	}
	for _, name := range []string{"root-key.pem", "issuer-key.pem", "root-ocsp-key.pem"} {
		if _, e := os.Stat(filepath.Join(online, name)); !os.IsNotExist(e) {
			t.Fatal("plaintext private key in online epoch")
		}
	}
	t.Log("standard existing-root CSR signing, distinct intermediate/OCSP delegate, monotonic root CRL revocation and actual ca-import CLI completed")
}
