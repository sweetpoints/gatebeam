package tlsidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReloadAndRevocationFloor(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	now := time.Now().UTC().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	write := func(name string, b []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("trust", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	var clientPair tls.Certificate
	pair := func(serial int64, usage x509.ExtKeyUsage) *x509.Certificate {
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"owned.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		b, e := x509.CreateCertificate(rand.Reader, c, ca, &leafKey.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		c, _ = x509.ParseCertificate(b)
		if usage == x509.ExtKeyUsageServerAuth {
			write("cert", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
			k, _ := x509.MarshalPKCS8PrivateKey(leafKey)
			write("key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
		}
		if usage == x509.ExtKeyUsageClientAuth {
			k, _ := x509.MarshalPKCS8PrivateKey(leafKey)
			clientPair, _ = tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
		}
		return c
	}
	pair(2, x509.ExtKeyUsageServerAuth)
	client := pair(99, x509.ExtKeyUsageClientAuth)
	crl := func(number int64, revoked bool) {
		r := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now.Add(-time.Second), NextUpdate: now.Add(20 * time.Minute)}
		if revoked {
			r.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: client.SerialNumber, RevocationTime: now}}
		}
		b, e := x509.CreateRevocationList(rand.Reader, r, ca, key)
		if e != nil {
			t.Fatal(e)
		}
		write("crl", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: b}))
	}
	crl(1, false)
	cfg := Config{CertificateFile: filepath.Join(dir, "cert"), KeyFile: filepath.Join(dir, "key"), TrustFile: filepath.Join(dir, "trust"), CRLFile: filepath.Join(dir, "crl"), StateFile: filepath.Join(dir, "floor"), NodeID: "owned", ServerName: "owned.test", ClientNames: []string{"owned.test"}}
	l, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	server.TLS = l.TLSConfig()
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	httpClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "owned.test", Certificates: []tls.Certificate{clientPair}}}}
	check := func(want bool) {
		t.Helper()
		r, e := httpClient.Get(server.URL)
		if e == nil {
			r.Body.Close()
		}
		if (e == nil) != want {
			t.Fatal("actual TLS handshake verdict", want, e)
		}
	}
	check(true)
	connection := tls.ConnectionState{PeerCertificates: []*x509.Certificate{client, ca}, VerifiedChains: [][]*x509.Certificate{{client, ca}}}
	active, e := l.Config()
	if e != nil || active.VerifyConnection(connection) != nil {
		t.Fatal("valid peer rejected", e)
	}
	pair(3, x509.ExtKeyUsageServerAuth)
	active, e = l.Config()
	if e != nil || active.Certificates[0].Leaf.SerialNumber.Int64() != 3 {
		t.Fatal("replacement not auto loaded", e)
	}
	write("key", []byte("partial replacement"))
	active, e = l.Config()
	if e != nil || active.Certificates[0].Leaf.SerialNumber.Int64() != 3 {
		t.Fatal("bad replacement lost valid active material", e)
	}
	crl(2, true)
	check(false)
	active, e = l.Config()
	if e != nil {
		t.Fatal(e)
	}
	if active.VerifyConnection(connection) == nil {
		t.Fatal("revoked peer accepted")
	}
	pair(4, x509.ExtKeyUsageServerAuth)
	saved, e := os.ReadFile(cfg.StateFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(cfg.StateFile); e != nil {
		t.Fatal(e)
	}
	if _, e = New(cfg); e == nil {
		t.Fatal("missing status state accepted despite persistent minimum")
	}
	if e = os.WriteFile(cfg.StateFile, saved, 0600); e != nil {
		t.Fatal(e)
	}
	crl(1, false)
	restarted, e := New(cfg)
	if e == nil {
		active, e = restarted.Config()
		if e == nil && active.VerifyConnection(connection) == nil {
			t.Fatal("old CRL revived revoked peer after restart")
		}
	}
	// A valid replacement trust root takes effect on the running loader.
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	next := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "replacement root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	nextDER, e := x509.CreateCertificate(rand.Reader, next, next, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(nextDER)
	write("trust", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nextDER}))
	pair(5, x509.ExtKeyUsageServerAuth)
	crl(1, false)
	active, e = l.Config()
	if e != nil {
		t.Fatal("valid replacement trust did not load", e)
	}
	if active.VerifyConnection(connection) == nil {
		t.Fatal("removed root still trusted by live listener")
	}
	// Loss of the active certificate after its expiry cannot report readiness.
	l.pair.Leaf.NotAfter = time.Now().Add(-time.Second)
	write("key", []byte("no valid replacement"))
	if l.Ready() == nil {
		t.Fatal("expired retained identity reported ready")
	}

}
