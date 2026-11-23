package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	app "gatebeam/internal/modules/certificates/application"
	material "gatebeam/internal/modules/certificates/infrastructure/crypto"
	"math/big"
	"testing"
	"time"
)

func TestPinnedTrustCannotBeReplacedByBundledRoot(t *testing.T) {
	now := time.Now()
	root := func(serial int64) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "same issuer name"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		c, _ = x509.ParseCertificate(der)
		return c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	_, _, trusted := root(1)
	issuer, issuerKey, bundled := root(2)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{"entry.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, issuerKey)
	if e != nil {
		t.Fatal(e)
	}
	cert := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), bundled...)
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	spec := app.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "import", TrustID: "pinned", TrustRevision: 1}
	if _, e = (material.Crypto{}).Inspect(spec, cert, keyPEM, now, trusted); e == nil {
		t.Fatal("same-DN bundled root replaced pinned trust")
	}
	if _, e = (material.Crypto{}).Inspect(spec, cert, keyPEM, now, bundled); e != nil {
		t.Fatal("correct pinned trust rejected", e)
	}
}
