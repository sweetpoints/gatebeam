package pkicrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/secrets"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func certificate(t *testing.T, tmpl, parent *x509.Certificate, pub, sign *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	b, e := x509.CreateCertificate(rand.Reader, tmpl, parent, &pub.PublicKey, sign)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(b)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func fixture(t *testing.T, mutate func(*x509.Certificate), rootKey bool) (Config, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	rk := key(t)
	ik := key(t)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 1}
	root := certificate(t, rt, rt, rk, rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "online test issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	if mutate != nil {
		mutate(it)
	}
	if rootKey {
		ik = rk
	}
	inter := certificate(t, it, root, ik, rk)
	cfg := Config{CertificateFile: filepath.Join(dir, "issuer.pem"), RootFile: filepath.Join(dir, "root.pem"), SignerFile: filepath.Join(dir, "issuer.age"), IdentityFile: filepath.Join(dir, "identity")}
	if e := secrets.EnsureIdentity(cfg.IdentityFile); e != nil {
		t.Fatal(e)
	}
	for path, c := range map[string]*x509.Certificate{cfg.CertificateFile: inter, cfg.RootFile: root} {
		if e := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeKey(t, cfg, ik)
	return cfg, inter, ik
}
func writeKey(t *testing.T, cfg Config, k *ecdsa.PrivateKey) {
	t.Helper()
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	s, e := secrets.New(cfg.IdentityFile)
	if e != nil {
		t.Fatal(e)
	}
	b, e = s.Seal("pki-online-issuer", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(cfg.SignerFile, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestOnlineCARequiresValidIntermediateAndKeyMatch(t *testing.T) {
	cfg, _, _ := fixture(t, nil, false)
	if _, e := LoadIssuer(cfg); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*x509.Certificate){"expired": func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, "future": func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }, "not-ca": func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false }, "no-certsign": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }, "pathlen": func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }, "wrong-purpose": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} }}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, _, _ := fixture(t, mut, false)
			if _, e := LoadIssuer(cfg); e == nil {
				t.Fatal("invalid issuer accepted")
			}
		})
	}
	t.Run("mismatched-key", func(t *testing.T) {
		cfg, _, _ := fixture(t, nil, false)
		writeKey(t, cfg, key(t))
		if _, e := LoadIssuer(cfg); e == nil {
			t.Fatal("key mismatch accepted")
		}
	})
	t.Run("root-key-rewrapped", func(t *testing.T) {
		cfg, _, _ := fixture(t, nil, true)
		if _, e := LoadIssuer(cfg); e == nil {
			t.Fatal("root key accepted online")
		}
	})
	t.Run("root-certificate", func(t *testing.T) {
		cfg, _, _ := fixture(t, nil, false)
		cfg.CertificateFile = cfg.RootFile
		if _, e := LoadIssuer(cfg); e == nil {
			t.Fatal("root accepted online")
		}
	})
}
func TestCSRAndIssuerConstraints(t *testing.T) {
	cfg, _, _ := fixture(t, nil, false)
	iss, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := domain.NewPolicy([]string{"server.internal.test"}, domain.ServerAuth)
	if e != nil {
		t.Fatal(e)
	}
	cases := map[string]*x509.CertificateRequest{
		"unauthorized-san": {DNSNames: []string{"other.internal.test"}},
		"ca-bit":           {DNSNames: []string{"server.internal.test"}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}}}},
		"extra-eku":        {DNSNames: []string{"server.internal.test"}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0}}}},
	}
	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			b, e := x509.CreateCertificateRequest(rand.Reader, csr, key(t))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = iss.SignCSR(b, policy, []string{"server.internal.test"}, big.NewInt(3), time.Now(), time.Hour); e == nil {
				t.Fatal("unsafe CSR accepted")
			}
		})
	}
}
func TestServerAndClientEKUAreDistinct(t *testing.T) {
	cfg, _, _ := fixture(t, nil, false)
	iss, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"server.internal.test"}}, key(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		usage domain.Usage
		eku   x509.ExtKeyUsage
	}{{domain.ServerAuth, x509.ExtKeyUsageServerAuth}, {domain.ClientAuth, x509.ExtKeyUsageClientAuth}} {
		p, e := domain.NewPolicy([]string{"server.internal.test"}, tc.usage)
		if e != nil {
			t.Fatal(e)
		}
		der, e := iss.SignCSR(csr, p, []string{"server.internal.test"}, big.NewInt(4), time.Now(), time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		c, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		if c.IsCA || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != tc.eku {
			t.Fatalf("wrong leaf usage: %+v", c.ExtKeyUsage)
		}
	}
}
func TestRandomSerialsArePositiveBoundedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		s, e := NewSerial()
		if e != nil {
			t.Fatal(e)
		}
		if s.Sign() <= 0 || s.BitLen() > 159 || seen[s.String()] {
			t.Fatal("invalid serial")
		}
		seen[s.String()] = true
	}
}

func TestIssuerRejectsInvalidRootConstraints(t *testing.T) {
	for name, mutate := range map[string]func(*x509.Certificate){
		"root-pathlen-zero": func(c *x509.Certificate) { c.MaxPathLen = 0; c.MaxPathLenZero = true },
		"root-expired":      func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		"root-no-crlsign":   func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, inter, ik := fixture(t, nil, false)
			b, e := os.ReadFile(cfg.RootFile)
			if e != nil {
				t.Fatal(e)
			}
			root, e := parseCertificate(b)
			if e != nil {
				t.Fatal(e)
			}
			mutate(root)
			rk := key(t)
			root.PublicKey = &rk.PublicKey
			root = certificate(t, root, root, rk, rk)
			inter = certificate(t, inter, root, ik, rk)
			for path, c := range map[string]*x509.Certificate{cfg.RootFile: root, cfg.CertificateFile: inter} {
				if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = LoadIssuer(cfg); e == nil {
				t.Fatal("invalid root constraints accepted")
			}
		})
	}
}
func TestCSRRejectsTamperingOrderMismatchAndInvalidSerial(t *testing.T) {
	cfg, _, _ := fixture(t, nil, false)
	iss, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p, e := domain.NewPolicy([]string{"a.internal.test", "b.internal.test"}, domain.ServerAuth)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"a.internal.test"}}, key(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = iss.SignCSR(csr, p, []string{"b.internal.test"}, big.NewInt(5), time.Now(), time.Hour); e == nil {
		t.Fatal("CSR does not match order")
	}
	for _, serial := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 159)} {
		if _, e = iss.SignCSR(csr, p, []string{"a.internal.test"}, serial, time.Now(), time.Hour); e == nil {
			t.Fatal("invalid serial accepted")
		}
	}
	csr[len(csr)-1] ^= 1
	if _, e = iss.SignCSR(csr, p, []string{"a.internal.test"}, big.NewInt(5), time.Now(), time.Hour); e == nil {
		t.Fatal("tampered CSR accepted")
	}
}
func TestIssuerRejectsSymlinkAndWorldReadableSecrets(t *testing.T) {
	cfg, _, _ := fixture(t, nil, false)
	if e := os.Chmod(cfg.SignerFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadIssuer(cfg); e == nil {
		t.Fatal("readable key accepted")
	}
	if e := os.Chmod(cfg.SignerFile, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(filepath.Dir(cfg.SignerFile), "key-link")
	if e := os.Symlink(cfg.SignerFile, link); e != nil {
		t.Fatal(e)
	}
	cfg.SignerFile = link
	if _, e := LoadIssuer(cfg); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestSigningHonorsIssuerNameConstraints(t *testing.T) {
	cfg, _, _ := fixture(t, func(c *x509.Certificate) {
		c.PermittedDNSDomainsCritical = true
		c.PermittedDNSDomains = []string{"restricted.internal.test"}
	}, false)
	iss, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p, e := domain.NewPolicy([]string{"other.internal.test"}, domain.ServerAuth)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"other.internal.test"}}, key(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = iss.SignCSR(csr, p, []string{"other.internal.test"}, big.NewInt(7), time.Now(), time.Hour); e == nil {
		t.Fatal("signed outside issuer name constraints")
	}
}

func TestLeafValidityBackdateIsBoundedByIssuerAndDoesNotExtendExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	policy, err := domain.NewPolicy([]string{"server.internal.test"}, domain.ServerAuth)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"server.internal.test"}}, key(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, recent := range []bool{false, true} {
		cfg, _, _ := fixture(t, func(c *x509.Certificate) {
			if recent {
				c.NotBefore = now.Add(-10 * time.Second)
			}
		}, false)
		issuer, err := LoadIssuer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		der, err := issuer.SignCSR(csr, policy, []string{"server.internal.test"}, big.NewInt(3), now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		want := now.Add(-time.Minute)
		if recent {
			want = issuer.Certificate.NotBefore
		}
		if !leaf.NotBefore.Equal(want) || !leaf.NotAfter.Equal(now.Add(time.Hour)) {
			t.Fatalf("validity interval got [%s,%s] want [%s,%s]", leaf.NotBefore, leaf.NotAfter, want, now.Add(time.Hour))
		}
		roots := x509.NewCertPool()
		roots.AddCert(issuer.Chain[0])
		intermediates := x509.NewCertPool()
		intermediates.AddCert(issuer.Certificate)
		// Standard verifier, including a consumer 100 ms behind the signing clock.
		opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now.Add(-100 * time.Millisecond), DNSName: "server.internal.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if _, err = leaf.Verify(opts); err != nil {
			t.Fatal(err)
		}
		opts.CurrentTime = want.Add(-time.Nanosecond)
		if _, err = leaf.Verify(opts); err == nil {
			t.Fatal("verifier accepted time before bounded validity")
		}
		if _, err = issuer.SignCSR(csr, policy, []string{"server.internal.test"}, big.NewInt(4), issuer.Certificate.NotBefore.Add(-time.Second), time.Hour); err == nil {
			t.Fatal("future issuer accepted")
		}
		if _, err = issuer.SignCSR(csr, policy, []string{"server.internal.test"}, big.NewInt(5), issuer.Certificate.NotAfter, time.Hour); err == nil {
			t.Fatal("expired issuer accepted")
		}
		late := issuer.Certificate.NotAfter.Add(-time.Minute)
		der, err = issuer.SignCSR(csr, policy, []string{"server.internal.test"}, big.NewInt(6), late, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err = x509.ParseCertificate(der)
		if err != nil || !leaf.NotAfter.Equal(issuer.Certificate.NotAfter) {
			t.Fatal("leaf exceeded issuer expiry", err)
		}
	}
}
