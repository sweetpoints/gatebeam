//go:build integration

package pkicrypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"gatebeam-ca/internal/modules/pki/domain"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenSSLChainUsageKeyAndStandardFormats(t *testing.T) {
	executable := os.Getenv("GATEBEAM_TEST_OPENSSL")
	if executable == "" {
		t.Fatal("GATEBEAM_TEST_OPENSSL must name the independently selected OpenSSL executable")
	}
	run := func(success bool, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, executable, args...).CombinedOutput()
		if success && e != nil || !success && !completedPurposeRejection(ctx, out, e) {
			t.Fatalf("OpenSSL %v: %v %s", args, e, out)
		}
		return out
	}
	t.Logf("independent verifier: %s", run(true, "version"))
	cfg, _, ik := fixture(t, nil, false)
	iss, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(ik)
	if e != nil {
		t.Fatal(e)
	}
	keyPath := write("owned-intermediate-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	certPublic := run(true, "x509", "-in", cfg.CertificateFile, "-pubkey", "-noout")
	keyPublic := run(true, "pkey", "-in", keyPath, "-pubout")
	if !bytes.Equal(certPublic, keyPublic) {
		t.Fatal("OpenSSL key mismatch")
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"server.internal.test"}}, key(t))
	if e != nil {
		t.Fatal(e)
	}
	csrPath := write("request.der", csr)
	run(true, "req", "-inform", "DER", "-in", csrPath, "-verify", "-noout")
	for _, tc := range []struct {
		usage          domain.Usage
		purpose, wrong string
	}{{domain.ServerAuth, "sslserver", "sslclient"}, {domain.ClientAuth, "sslclient", "sslserver"}} {
		policy, e := domain.NewPolicy([]string{"server.internal.test"}, tc.usage)
		if e != nil {
			t.Fatal(e)
		}
		der, e := iss.SignCSR(csr, policy, []string{"server.internal.test"}, big.NewInt(5), time.Now(), time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		path := write(tc.purpose+".der", der)
		pemPath := filepath.Join(dir, tc.purpose+".pem")
		run(true, "x509", "-inform", "DER", "-in", path, "-out", pemPath)
		run(true, "verify", "-CAfile", cfg.RootFile, "-untrusted", cfg.CertificateFile, "-purpose", tc.purpose, pemPath)
		run(false, "verify", "-CAfile", cfg.RootFile, "-untrusted", cfg.CertificateFile, "-purpose", tc.wrong, pemPath)
	}
}

func completedPurposeRejection(ctx context.Context, out []byte, err error) bool {
	var exit *exec.ExitError
	return ctx.Err() == nil && errors.As(err, &exit) && exit.Exited() && exit.ExitCode() == 2 && bytes.Contains(out, []byte("error 26 at 0 depth lookup: unsuitable certificate purpose")) && bytes.Contains(out, []byte("verification failed"))
}

func TestOpenSSLNegativeHarnessRejectsLaunchTimeoutAndKill(t *testing.T) {
	if mode := os.Getenv("GATEBEAM_OPENSSL_NEGATIVE_HELPER"); mode != "" {
		os.Stdout.WriteString("error 26 at 0 depth lookup: unsuitable certificate purpose\nerror leaf.pem: verification failed\n")
		switch mode {
		case "verified":
			os.Exit(2)
		case "other":
			os.Exit(1)
		case "killed":
			p, _ := os.FindProcess(os.Getpid())
			p.Kill()
		case "timeout":
			time.Sleep(time.Second)
		}
		os.Exit(0)
	}
	for _, mode := range []string{"missing", "timeout", "killed", "other", "verified"} {
		t.Run(mode, func(t *testing.T) {
			budget := 2 * time.Second
			if mode == "timeout" {
				budget = 20 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), budget)
			defer cancel()
			path := os.Args[0]
			if mode == "missing" {
				path = filepath.Join(t.TempDir(), "no-openssl")
			}
			cmd := exec.CommandContext(ctx, path, "-test.run=^TestOpenSSLNegativeHarnessRejectsLaunchTimeoutAndKill$")
			cmd.Env = append(os.Environ(), "GATEBEAM_OPENSSL_NEGATIVE_HELPER="+mode)
			out, err := cmd.CombinedOutput()
			if got := completedPurposeRejection(ctx, out, err); got != (mode == "verified") {
				t.Fatalf("%s incorrectly classified rejection=%v err=%v", mode, got, err)
			}
		})
	}
}
