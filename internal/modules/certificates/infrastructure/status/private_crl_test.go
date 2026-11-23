package status

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrivateCRLSourcePinsIssuerAndEndpoint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ = x509.ParseCertificate(der)
	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, cert, key)
	if e != nil {
		t.Fatal(e)
	}
	hit := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = r.URL.Path; w.Write(crl) }))
	defer server.Close()
	fp := fingerprint(cert)
	p := Profile{ID: "owned", Fingerprints: []string{fp}, CRLURLs: map[string]string{fp: server.URL + "/fixed.crl"}, OCSPURLs: map[string]string{fp: server.URL + "/ocsp"}, AllowedNetworks: []string{"127.0.0.1/32"}, ResolverServers: []string{"127.0.0.1:53"}}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	source, e := NewPrivateCRLs([]Profile{p}, trust)
	if e != nil {
		t.Fatal(e)
	}
	got, e := source.Fetch(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(got)
	if block == nil || !bytes.Equal(block.Bytes, crl) || hit != "/fixed.crl" {
		t.Fatal("pinned original CRL not fetched")
	}
	other := p
	other.ID = "ambiguous"
	other.CRLURLs = map[string]string{fp: server.URL + "/other"}
	if _, e = NewPrivateCRLs([]Profile{p, other}, trust); e == nil {
		t.Fatal("ambiguous issuer endpoint policies accepted")
	}
}
