package edge_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (c authority) intermediate(t *testing.T) authority {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "owned intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &k.PublicKey, c.key)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ := x509.ParseCertificate(der)
	return authority{cert, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
func (c authority) revocations(t *testing.T, serial *big.Int) []byte {
	t.Helper()
	list := &x509.RevocationList{Number: big.NewInt(time.Now().UnixNano()), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
	if serial != nil {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: serial, RevocationTime: time.Now().Add(-time.Minute)}}
	}
	der, e := x509.CreateRevocationList(rand.Reader, list, c.cert, c.key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
func parsed(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("missing certificate")
	}
	c, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestNativeUpstreamCRLChainAndNoRetry(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		name := "good"
		if revoked {
			name = "revoked"
		}
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			root := newCA(t, "upstream root")
			inter := root.intermediate(t)
			a, key := inter.leaf(t, "a.internal.test", false)
			b, bkey := inter.leaf(t, "b.internal.test", false)
			os.WriteFile(filepath.Join(f.root, "a.pem"), append(a, inter.pem...), 0600)
			os.WriteFile(filepath.Join(f.root, "a.key"), key, 0600)
			os.WriteFile(filepath.Join(f.root, "b.pem"), append(b, inter.pem...), 0600)
			os.WriteFile(filepath.Join(f.root, "b.key"), bkey, 0600)
			trust := edge.Material{Revision: 1, TrustPEM: append(append([]byte{}, root.pem...), inter.pem...), CRLPEM: append(root.revocations(t, nil), inter.revocations(t, nil)...)}
			f.state.Materials["trust"] = trust
			f.snapshot.Targets[0].Config.Members[1].Weight = 1
			f.addSite(t, "crl.test")
			incomplete := trust
			incomplete.CRLPEM = inter.revocations(t, nil)
			f.state.Materials["trust"] = incomplete
			if _, e := (nginx.Compiler{}).Compile(f.snapshot, f.state); e == nil {
				t.Fatal("missing root issuer CRL accepted")
			}
			f.state.Materials["trust"] = trust
			good, e := (nginx.Compiler{}).Compile(f.snapshot, f.state)
			if e != nil {
				t.Fatal(e)
			}

			if revoked {
				trust.CRLPEM = append(root.revocations(t, nil), inter.revocations(t, parsed(t, a).SerialNumber)...)
				f.state.Materials["trust"] = trust
				bad, e := (nginx.Compiler{}).Compile(f.snapshot, f.state)
				if e != nil {
					t.Fatal(e)
				}
				if good.Digest == bad.Digest {
					t.Fatal("CRL generation did not change artifact")
				}
			}
			f.start(t)
			status, _ := request(t, f.client("crl.test", nil), "crl.test", "/", "", nil)
			want := 200
			if revoked {
				want = 502
			}
			if status != want {
				t.Fatalf("revoked=%v got%d want%d; retry must stay disabled", revoked, status, want)
			}
			next, data := request(t, f.client("crl.test", nil), "crl.test", "/", "", nil)
			if next != 200 || data["sni"] != "b.internal.test" {
				t.Fatalf("second member is not independently healthy: %d %v", next, data)
			}
			t.Logf("upstream signed chain CRL revoked=%v: selected-first=%d next-member=%d", revoked, status, next)
			if !strings.Contains(string(good.Files["nginx.conf"]), "proxy_ssl_crl ") {
				t.Fatal("upstream CRL directive missing")
			}
		})
	}
}
func TestNativeHostnameOCSPStatusesAndTimeout(t *testing.T) {
	f := setup(t)
	ca := newCA(t, "owned client OCSP CA")
	responses := map[string]string{}
	for _, kind := range []string{"good", "revoked", "unknown", "timeout"} {
		name := kind + ".ocsp.test"
		c := f.addSite(t, name)
		c.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "client-trust", Revision: 1}, Depth: 2, Revocation: "ocsp"}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, OCSPServer: []string{"http://ocsp.owned.test:9080/" + kind + "/"}}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
		if e != nil {
			t.Fatal(e)
		}
		key, _ := x509.MarshalPKCS8PrivateKey(k)
		pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
		if e != nil {
			t.Fatal(e)
		}
		f.clients[kind] = pair
		status := ocsp.Good
		if kind == "revoked" {
			status = ocsp.Revoked
		}
		if kind == "unknown" {
			status = ocsp.Unknown
		}
		response, e := ocsp.CreateResponse(ca.cert, ca.cert, ocsp.Response{SerialNumber: tmpl.SerialNumber, Status: status, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedAt: time.Now().Add(-time.Minute)}, ca.key)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := ocsp.ParseResponse(response, ca.cert); e != nil {
			t.Fatal(e)
		}
		os.WriteFile(filepath.Join(f.root, kind+".ocsp"), response, 0600)
		responses[kind] = tmpl.SerialNumber.String()
	}
	f.state.Materials["client-trust"] = edge.Material{Revision: 1, TrustPEM: ca.pem, OCSP: &edge.OCSPState{Generation: "owned-1", ValidUntil: time.Now().Add(time.Hour), ResponderNames: []string{"ocsp.owned.test"}}}
	f.state.OCSPResolver = &edge.ResolverState{Generation: "owned-dns", Servers: []netip.AddrPort{netip.MustParseAddrPort(f.ip + ":1053")}, TimeoutSeconds: 1, ValidForSeconds: 1}
	f.state.TLSHandshakeTimeoutSeconds = 2
	config, _ := json.Marshal(struct {
		Address string
		Serials map[string]string
	}{f.ip, responses})
	os.WriteFile(filepath.Join(f.root, "revocation.json"), config, 0600)
	command(t, "docker", "exec", "-d", f.name, "sh", "-c", "exec /fixture/backend /fixture revocation >/proc/1/fd/1 2>/proc/1/fd/2")
	command(t, "docker", "exec", f.name, "sh", "-c", "for i in $(seq 1 30); do wget -qO- http://127.0.0.1:9080/ready && exit 0; sleep 0.1; done; exit 1")
	f.start(t)
	for _, kind := range []string{"good", "revoked", "unknown", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			pair := f.clients[kind]
			client := f.client(kind+".ocsp.test", &pair)
			client.Timeout = 6 * time.Second
			start := time.Now()
			resp, e := client.Get("https://" + kind + ".ocsp.test/")
			elapsed := time.Since(start)
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			t.Logf("standard hostname OCSP %s: status=%d elapsed=%s transport_error=%v", kind, status, elapsed, e)
			if kind == "good" {
				if e != nil || resp.StatusCode != 200 {
					t.Fatalf("valid hostname OCSP got%v err%v", resp, e)
				}
			} else if e == nil && resp.StatusCode == 200 {
				t.Fatal("invalid/unavailable OCSP accepted")
			}
			if resp != nil {
				resp.Body.Close()
			}
			if kind == "timeout" && (elapsed < time.Second || elapsed > 4*time.Second) {
				t.Fatalf("Nginx handshake bound not enforced: %s err%v", elapsed, e)
			}
		})
	}
	logs := command(t, "docker", "logs", f.name)
	if !strings.Contains(logs, "owned DNS ocsp.owned.test") || !strings.Contains(logs, "owned OCSP good") || !strings.Contains(logs, "owned OCSP timeout") {
		t.Fatal("hostname DNS/responder fixture did not execute", logs)
	}
}
