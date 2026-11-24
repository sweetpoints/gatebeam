package pkicrypto

import (
	"context"
	"crypto/x509"
	"fmt"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func TestRootStatusDelegationUnknownIssuerAndBoundedFreshness(t *testing.T) {
	dir := t.TempDir()
	online := filepath.Join(dir, "online")
	if e := (Bootstrapper{}).Generate(context.Background(), application.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: online, RootName: "root", IntermediateName: "issuer", StatusOrigin: "http://status.internal.test"}); e != nil {
		t.Fatal(e)
	}
	issuer, e := LoadIssuer(Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	root, e := LoadRootStatus(issuer, filepath.Join(online, "root-ocsp.pem"), filepath.Join(online, "root-ocsp.age"), filepath.Join(online, "identity.agekey"), filepath.Join(online, "root.crl.der"))
	if e != nil {
		t.Fatal(e)
	}
	makeID := func(c *x509.Certificate) status.CertID {
		b, e := ocsp.CreateRequest(c, root.Root, nil)
		if e != nil {
			t.Fatal(e)
		}
		r, e := ocsp.ParseRequest(b)
		if e != nil {
			t.Fatal(e)
		}
		return status.CertID{Hash: r.HashAlgorithm.String(), NameHash: r.IssuerNameHash, KeyHash: r.IssuerKeyHash, Serial: domain.Serial(fmt.Sprintf("%040x", r.SerialNumber))}
	}
	now := time.Now().UTC()
	id := makeID(issuer.Certificate)
	for _, tc := range []struct {
		id   status.CertID
		want int
	}{{id, ocsp.Good}, {makeID(&x509.Certificate{SerialNumber: big.NewInt(42)}), ocsp.Unknown}} {
		v, e := root.Response(context.Background(), tc.id, issuer.Certificate.Raw, now)
		if e != nil {
			t.Fatal(e)
		}
		r, e := ocsp.ParseResponse(v.DER, root.Root)
		if e != nil || r.Status != tc.want || r.Certificate == nil || r.Certificate.CheckSignatureFrom(root.Root) != nil || r.NextUpdate.After(root.Credential.NotAfter) || r.NextUpdate.After(now.Add(5*time.Minute)) {
			t.Fatal("root status response invalid", e)
		}
	}
	wrong := id
	wrong.KeyHash = append([]byte(nil), id.KeyHash...)
	wrong.KeyHash[0] ^= 1
	if _, e = root.Response(context.Background(), wrong, issuer.Certificate.Raw, now); e == nil {
		t.Fatal("wrong root issuer accepted")
	}
	if _, e = root.Response(context.Background(), id, []byte("changed public issuer"), now); e == nil {
		t.Fatal("unregistered issuer accepted")
	}
	if _, e = root.Response(context.Background(), id, issuer.Certificate.Raw, root.Credential.NotAfter); e == nil {
		t.Fatal("expired root delegation accepted")
	}
	for _, mutation := range []string{"root-key", "issuer-key", "ca", "wrong-eku", "key-mismatch", "missing-intermediate"} {
		t.Run(mutation, func(t *testing.T) {
			copy := *root
			cert := *root.Credential
			copy.Credential = &cert
			switch mutation {
			case "missing-intermediate":
				copy.Intermediate = nil
			case "root-key":
				cert.RawSubjectPublicKeyInfo = root.Root.RawSubjectPublicKeyInfo
			case "issuer-key":
				cert.RawSubjectPublicKeyInfo = issuer.Certificate.RawSubjectPublicKeyInfo
			case "ca":
				cert.IsCA = true
			case "wrong-eku":
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "key-mismatch":
				copy.key = key(t)
			}
			if e := copy.Validate(now); e == nil {
				t.Fatal("invalid root delegation accepted", mutation)
			}
		})
	}
}
