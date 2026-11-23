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
	client                        *status.Client
	trust                         app.TrustBundle
	bundle                        []byte
	now                           time.Time
	rootUnknown, wrongID, expired *atomic.Bool
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
	var intermediate *x509.Certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer, key := root, rootKey
		if strings.Contains(r.URL.Path, "intermediate") {
			issuer, key = intermediate, intermediateKey
		}
		if strings.HasPrefix(r.URL.Path, "/crl/") {
			next := now.Add(10 * time.Minute)
			if expired.Load() {
				next = now.Add(-time.Minute)
			}
			raw, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-2 * time.Minute), NextUpdate: next}, issuer, key)
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
		if wrongID.Load() {
			copyIssuer := *issuer
			copyIssuer.RawSubject = []byte("wrong signed issuer identity")
			issuer = &copyIssuer
		}
		raw, e := ocsp.CreateResponse(issuer, issuer, ocsp.Response{Status: verdict, SerialNumber: request.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(4 * time.Minute), IssuerHash: request.HashAlgorithm}, key)
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
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "status intermediate"}, IsCA: true, BasicConstraintsValid: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, OCSPServer: []string{origin + "/ocsp/root"}}
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
	return standardFixture{client, trust, bundle, now, &rootUnknown, &wrongID, &expired}
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
