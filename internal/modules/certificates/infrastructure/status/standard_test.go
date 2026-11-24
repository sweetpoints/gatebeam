package status_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/status"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ocsp"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type standardFixture struct {
	client                                *status.Client
	trust                                 app.TrustBundle
	bundle                                []byte
	now                                   time.Time
	rootUnknown, wrongID, expired         *atomic.Bool
	leafExpired, leafRevoked, leafUnknown *atomic.Bool
	leaf                                  app.StoredVersion
}

func newStandardFixture(t *testing.T) standardFixture {
	now := time.Now().UTC()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "status root"}, IsCA: true, BasicConstraintsValid: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, _ := x509.ParseCertificate(rootDER)
	var rootUnknown atomic.Bool
	var wrongID atomic.Bool
	var expired atomic.Bool
	var leafExpired, leafRevoked, leafUnknown atomic.Bool
	var intermediate *x509.Certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer, key := root, rootKey
		if strings.Contains(r.URL.Path, "intermediate") {
			issuer, key = intermediate, intermediateKey
		}
		if strings.HasPrefix(r.URL.Path, "/crl/") {
			next := now.Add(10 * time.Minute)
			if expired.Load() || (issuer == intermediate && leafExpired.Load()) {
				next = now.Add(-time.Minute)
			}
			list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-2 * time.Minute), NextUpdate: next}
			if issuer == intermediate && leafRevoked.Load() {
				list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now.Add(-time.Minute)}}
			}
			raw, e := x509.CreateRevocationList(rand.Reader, list, issuer, key)
			if e != nil {
				t.Error(e)
				http.Error(w, "fixture", 500)
				return
			}
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(raw)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		request, e := ocsp.ParseRequest(body)
		if e != nil {
			http.Error(w, "fixture", 400)
			return
		}
		verdict := ocsp.Unknown
		if request.SerialNumber.Cmp(intermediate.SerialNumber) == 0 && issuer == root && !rootUnknown.Load() {
			verdict = ocsp.Good
		}
		if request.SerialNumber.Int64() == 3 && issuer == intermediate && !leafUnknown.Load() {
			verdict = ocsp.Good
		}
		if wrongID.Load() {
			copyIssuer := *issuer
			copyIssuer.RawSubject = []byte("wrong signed issuer identity")
			issuer = &copyIssuer
		}
		updated := now.Add(-time.Minute)
		if issuer == intermediate && request.SerialNumber.Int64() == 3 {
			updated = now.Truncate(time.Minute).Add(time.Second)
		}
		raw, e := ocsp.CreateResponse(issuer, issuer, ocsp.Response{Status: verdict, SerialNumber: request.SerialNumber, ThisUpdate: updated, NextUpdate: now.Add(4 * time.Minute), IssuerHash: request.HashAlgorithm}, key)
		if e != nil {
			t.Error(e)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	origin := "http://status.test:" + port
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "status intermediate"}, IsCA: true, BasicConstraintsValid: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, OCSPServer: []string{origin + "/ocsp/root"}, CRLDistributionPoints: []string{origin + "/crl/root"}}
	intermediateDER, e := x509.CreateCertificate(rand.Reader, template, root, &intermediateKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	intermediate, _ = x509.ParseCertificate(intermediateDER)
	packet, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	resolver := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Name == "status.test." && q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("127.0.0.1")})
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = resolver.ActivateAndServe() }()
	t.Cleanup(func() { _ = resolver.Shutdown() })
	fingerprint := func(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
	rf, cf := fingerprint(rootDER), fingerprint(intermediateDER)
	profile := status.Profile{ID: "owned", Fingerprints: []string{rf, cf}, CRLURLs: map[string]string{rf: origin + "/crl/root", cf: origin + "/crl/intermediate"}, OCSPURLs: map[string]string{rf: origin + "/ocsp/root", cf: origin + "/ocsp/intermediate"}, ResolverServers: []string{packet.LocalAddr().String()}, AllowedNetworks: []string{"127.0.0.1/32"}}
	client, e := status.New([]status.Profile{profile})
	if e != nil {
		t.Fatal(e)
	}
	trust := app.TrustBundle{Purpose: "clientAuth", StatusProfile: "owned", Fingerprints: []string{rf, cf}}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})...)
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), DNSNames: []string{"leaf.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		OCSPServer:  []string{origin + "/ocsp/intermediate"}, CRLDistributionPoints: []string{origin + "/crl/intermediate"},
	}
	leafDER, e := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf := app.StoredVersion{
		Version: app.Version{
			Serial: fmt.Sprintf("%040x", leafTemplate.SerialNumber), Purpose: "clientAuth", LeafFingerprint: fingerprint(leafDER),
			Issuer: cf, IssuerKeyFingerprint: fingerprint(intermediate.RawSubjectPublicKeyInfo),
		},
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
	}
	return standardFixture{
		client: client, trust: trust, bundle: bundle, now: now,
		rootUnknown: &rootUnknown, wrongID: &wrongID, expired: &expired,
		leafExpired: &leafExpired, leafRevoked: &leafRevoked, leafUnknown: &leafUnknown, leaf: leaf,
	}
}
func TestStandardUnknownReadinessAndKnownIntermediateStatus(t *testing.T) {
	f := newStandardFixture(t)
	client, trust, bundle, now := f.client, f.trust, f.bundle, f.now
	rootUnknown, wrongID, expired := f.rootUnknown, f.wrongID, f.expired
	attestation, e := client.Attest(context.Background(), trust, bundle, now)
	if e != nil {
		t.Fatal("valid standard status", e)
	}
	if !attestation.UnknownResponderReady || attestation.Generation == "" || len(attestation.CRLPEM) == 0 || attestation.ValidUntil.After(now.Add(4*time.Minute)) {
		t.Fatal("invalid readiness evidence", attestation)
	}
	rootUnknown.Store(true)
	if _, e = client.Attest(context.Background(), trust, bundle, now); e == nil {
		t.Fatal("actual intermediate Unknown treated as Good")
	}
	rootUnknown.Store(false)
	wrongID.Store(true)
	if _, e = client.Attest(context.Background(), trust, bundle, now); e == nil {
		t.Fatal("signed wrong-issuer CertID accepted")
	}
	wrongID.Store(false)
	expired.Store(true)
	if _, e = client.Attest(context.Background(), trust, bundle, now); e == nil {
		t.Fatal("expired CRL accepted")
	}
}

func TestPinnedLeafStatusFailsClosed(t *testing.T) {
	f := newStandardFixture(t)
	verifier, err := status.NewLeafVerifier(f.client, f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, managed := range []bool{true, false} {
		if err := verifier.Verify(t.Context(), f.leaf, managed, f.now.Add(time.Second)); err != nil {
			t.Fatalf("valid leaf rejected (managed=%t): %v", managed, err)
		}
	}
	for _, scenario := range []struct {
		name  string
		fault *atomic.Bool
	}{
		{"expired issuer CRL", f.leafExpired},
		{"revoked leaf with good OCSP", f.leafRevoked},
		{"unknown leaf", f.leafUnknown},
		{"unknown intermediate", f.rootUnknown},
		{"wrong OCSP issuer", f.wrongID},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			scenario.fault.Store(true)
			defer scenario.fault.Store(false)
			if err := verifier.Verify(t.Context(), f.leaf, false, f.now.Add(time.Second)); err == nil {
				t.Fatal("unsafe imported leaf accepted")
			}
		})
	}
	tampered := f.leaf
	tampered.LeafFingerprint = strings.Repeat("0", 64)
	if err := verifier.Verify(t.Context(), tampered, true, f.now.Add(time.Second)); err == nil {
		t.Fatal("leaf different from the stored fingerprint was accepted")
	}
}
