package statuscache_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"gatebeam/internal/modules/certificates/application/statuscache"
	"gatebeam/internal/modules/certificates/infrastructure/ocspcache"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestOCSPRejectsNonceIssuerExpiryAndRevokedFloor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	fp := hex.EncodeToString(sum[:])
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	request, _ := ocsp.CreateRequest(leaf, issuer, nil)
	response := func(status int, this, next time.Time) []byte {
		d, e := ocsp.CreateResponse(issuer, issuer, ocsp.Response{SerialNumber: leaf.SerialNumber, Status: status, ThisUpdate: this, NextUpdate: next, RevokedAt: now.Add(-time.Minute)}, key)
		if e != nil {
			t.Fatal(e)
		}
		return d
	}
	root := filepath.Join(t.TempDir(), "cache")
	store, err := ocspcache.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	service, err := statuscache.New(store, cacheVerifier(t, issuer), nil)
	if err != nil {
		t.Fatal(err)
	}
	req := statuscache.Request{DER: request, IssuerFingerprint: fp}
	good := response(ocsp.Good, now.Add(-time.Second), now.Add(time.Minute))
	if _, err = service.Lookup(t.Context(), req, now); err == nil {
		t.Fatal("cache miss invented good")
	}
	if err = service.Observe(t.Context(), req, good, now); err != nil {
		t.Fatal(err)
	}
	store, err = ocspcache.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	service, err = statuscache.New(store, cacheVerifier(t, issuer), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Lookup(t.Context(), req, now)
	if err != nil || !bytes.Equal(got, good) {
		t.Fatalf("signed DER not preserved across restart: %v", err)
	}
	// Nonce is request-specific. A cached no-nonce response cannot answer it.
	var withNonce struct {
		Data struct {
			Requests   []asn1.RawValue
			Extensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
		}
	}
	if _, err = asn1.Unmarshal(request, &withNonce); err != nil {
		t.Fatal(err)
	}
	nonceValue, _ := asn1.Marshal([]byte("0123456789abcdef"))
	withNonce.Data.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}, Value: nonceValue}}
	nonceDER, err := asn1.Marshal(withNonce)
	if err != nil {
		t.Fatal(err)
	}
	nonceReq := statuscache.Request{DER: nonceDER, IssuerFingerprint: fp}
	if err = service.Observe(t.Context(), nonceReq, good, now); err == nil {
		t.Fatal("nonce mismatch accepted")
	}
	if _, err = service.Lookup(t.Context(), nonceReq, now); err == nil {
		t.Fatal("no-nonce good replayed to nonce request")
	}
	handler := ocspcache.Handler(service)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		target := "/ocsp"
		if method == http.MethodGet {
			target += "/" + base64.StdEncoding.EncodeToString(request)
		}
		httpReq := httptest.NewRequest(method, target, bytes.NewReader(request))
		httpReq.Header.Set("Content-Type", "application/ocsp-request")
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, httpReq)
		if writer.Code != 200 || !bytes.Equal(writer.Body.Bytes(), good) {
			t.Fatalf("standard HTTP OCSP %s rejected good DER: %d", method, writer.Code)
		}
	}
	now = time.Now().UTC().Add(time.Second)
	for _, kind := range []string{"future", "missing-expiry", "expired", "wrong-signature", "wrong-issuer"} {
		t.Run(kind, func(t *testing.T) {
			bad := good
			r := req
			switch kind {
			case "future":
				bad = response(ocsp.Good, now.Add(time.Second), now.Add(time.Minute))
			case "missing-expiry":
				bad = response(ocsp.Good, now.Add(-time.Second), time.Time{})
			case "expired":
				bad = response(ocsp.Good, now.Add(-time.Minute), now)
			case "wrong-signature":
				bad = bytes.Clone(good)
				bad[len(bad)-1] ^= 1
			case "wrong-issuer":
				r.IssuerFingerprint = "unknown-issuer"
			}
			if err := service.Observe(t.Context(), r, bad, now); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
	revoked := response(ocsp.Revoked, now, now.Add(time.Minute))
	if err = service.Observe(t.Context(), req, revoked, now); err != nil {
		t.Fatal(err)
	}
	if err = service.Observe(t.Context(), req, good, now); err == nil {
		t.Fatal("old good overwrote known revoked")
	}
	store, _ = ocspcache.NewStore(root)
	service, _ = statuscache.New(store, cacheVerifier(t, issuer), nil)
	if _, err = service.Lookup(t.Context(), req, now); err == nil {
		t.Fatal("restart lost revocation floor")
	}
	if _, err = service.Lookup(t.Context(), req, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired response returned")
	}
	if _, err = service.Lookup(t.Context(), req, now); err == nil {
		t.Fatal("clock rollback accepted")
	}
}

func cacheVerifier(t *testing.T, issuer *x509.Certificate) *ocspcache.Verifier {
	t.Helper()
	verifier, err := ocspcache.NewVerifier([][]byte{issuer.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}
