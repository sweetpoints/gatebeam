package pkicrypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"gatebeam/internal/modules/pki/application"
	"gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/modules/pki/domain"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertIDIssuerAndUnknownAreNotGood(t *testing.T) {
	cfg, _, _ := fixture(t, nil, false)
	issuer, e := LoadIssuer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	responder := NewStatusSigner(issuer)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	request, e := ocsp.CreateRequest(leaf, issuer.Certificate, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if e != nil {
		t.Fatal(e)
	}
	req, e := ocsp.ParseRequest(request)
	if e != nil {
		t.Fatal(e)
	}
	id := status.CertID{Hash: "SHA-256", NameHash: req.IssuerNameHash, KeyHash: req.IssuerKeyHash, Serial: domain.Serial("000000000000000000000000000000000000002a")}
	if _, e = responder.MatchIssuer(id); e != nil {
		t.Fatal(e)
	}
	wrong := id
	wrong.KeyHash = append([]byte(nil), id.KeyHash...)
	wrong.KeyHash[0] ^= 1
	if _, e = responder.MatchIssuer(wrong); e == nil {
		t.Fatal("wrong issuer key accepted")
	}
	wrong = id
	wrong.NameHash = append([]byte(nil), id.NameHash...)
	wrong.NameHash[0] ^= 1
	if _, e = responder.MatchIssuer(wrong); e == nil {
		t.Fatal("wrong issuer subject accepted")
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, state := range []domain.CertificateStatus{domain.StatusGood, domain.StatusUnknown, domain.StatusRevoked} {
		response, e := responder.SignOCSP(id, status.Record{State: state, Revocation: domain.Revocation{Serial: id.Serial, Reason: 1, At: now.Add(-time.Minute)}}, now)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := ocsp.ParseResponse(response.DER, issuer.Certificate)
		if e != nil {
			t.Fatal(e)
		}
		expected := map[domain.CertificateStatus]int{domain.StatusGood: ocsp.Good, domain.StatusUnknown: ocsp.Unknown, domain.StatusRevoked: ocsp.Revoked}[state]
		if parsed.Status != expected || parsed.Certificate == nil || bytes.Equal(parsed.Certificate.RawSubjectPublicKeyInfo, issuer.Certificate.RawSubjectPublicKeyInfo) || len(parsed.Certificate.ExtKeyUsage) != 1 || parsed.Certificate.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning || parsed.ThisUpdate.After(now) || !parsed.NextUpdate.After(now) {
			t.Fatal("invalid delegated response", state)
		}
	}
}

func TestCRLBootstrapExportsPublicRootStatus(t *testing.T) {
	dir := t.TempDir()
	cmd := application.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: filepath.Join(dir, "online"), RootName: "root", IntermediateName: "issuer"}
	if e := (Bootstrapper{}).Generate(context.Background(), cmd); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(cmd.OnlineDirectory, "root.crl.der"))
	if e != nil {
		t.Fatal("offline ceremony must export public root CRL", e)
	}
	rootPEM, e := os.ReadFile(filepath.Join(cmd.OnlineDirectory, "root.pem"))
	if e != nil {
		t.Fatal(e)
	}
	root, e := parseCertificate(rootPEM)
	if e != nil {
		t.Fatal(e)
	}
	list, e := x509.ParseRevocationList(b)
	if e != nil || list.CheckSignatureFrom(root) != nil || !list.NextUpdate.After(time.Now()) {
		t.Fatal("root CRL invalid", e)
	}
}

func TestStatusRejectsInvalidDelegatedOCSPCredential(t *testing.T) {
	for _, kind := range []string{"wrong-eku", "expired", "wrong-key", "issuer-key"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _, _ := fixture(t, nil, false)
			issuer, e := LoadIssuer(cfg)
			if e != nil {
				t.Fatal(e)
			}
			signer := NewStatusSigner(issuer)
			now := time.Now().UTC().Truncate(time.Second)
			request, e := ocsp.CreateRequest(&x509.Certificate{SerialNumber: big.NewInt(42)}, issuer.Certificate, nil)
			if e != nil {
				t.Fatal(e)
			}
			req, e := ocsp.ParseRequest(request)
			if e != nil {
				t.Fatal(e)
			}
			id := status.CertID{Hash: req.HashAlgorithm.String(), NameHash: req.IssuerNameHash, KeyHash: req.IssuerKeyHash, Serial: "000000000000000000000000000000000000002a"}
			if e = signer.delegated(now); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "wrong-eku":
				signer.responder.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "expired":
				issuer.Certificate.NotAfter = now.Add(-time.Second)
				signer.issuer = issuer
			case "wrong-key":
				signer.key = key(t)
			case "issuer-key":
				signer.responder = issuer.Certificate
				signer.key = issuer.Signer
			}
			if _, e = signer.SignOCSP(id, status.Record{State: domain.StatusGood}, now); e == nil {
				t.Fatal("invalid OCSP delegation accepted", kind)
			}
		})
	}
}
