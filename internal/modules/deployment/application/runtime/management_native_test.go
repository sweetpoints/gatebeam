//go:build native

package runtime_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeManagementPeerFallbackDoesNotReplayWrites(t *testing.T) {
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "management lab CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(trust)
	leaf := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte, tls.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"management.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		kb, _ := x509.MarshalPKCS8PrivateKey(key)
		cert, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
		pair, e := tls.X509KeyPair(cert, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		return cert, keyPEM, pair
	}
	serverCert, serverKey, serverPair := leaf(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey, _ := leaf(3, x509.ExtKeyUsageClientAuth)
	var private string
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		prefix, e := netip.ParsePrefix(address.String())
		if e == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() {
			private = prefix.Addr().String()
			break
		}
	}
	if private == "" {
		t.Fatal("native private interface required")
	}
	var writesA, writesB atomic.Int32
	start := func(primary bool) *httptest.Server {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				_, _ = io.Copy(io.Discard, r.Body)
				if primary {
					writesA.Add(1)
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
					return
				}
				writesB.Add(1)
			}
			prefix := "B:"
			if primary {
				prefix = "A:"
			}
			_, _ = io.WriteString(w, prefix+r.Header.Get("Cookie"))
		})
		s := httptest.NewUnstartedServer(h)
		s.Listener.Close()
		listener, e := net.Listen("tcp", net.JoinHostPort(private, "0"))
		if e != nil {
			t.Fatal(e)
		}
		s.Listener = listener
		s.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	a, b := start(true), start(false)
	root := filepath.Join(t.TempDir(), "runtime")
	disk, e := fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	process, e := nginx.NewProcess("/usr/sbin/nginx", root)
	if e != nil {
		t.Fatal(e)
	}
	defer process.Stop(context.Background())
	plan := edge.Plan{Snapshot: app.Snapshot{Version: "management-peer"}, Runtime: edge.RuntimeState{Generation: "g1", Now: now, LogDirectory: filepath.Join(root, "logs"), Management: &edge.ManagementTLS{Domain: "management.test", APIAddress: netip.MustParseAddrPort(a.Listener.Addr().String()), PeerAPIAddress: netip.MustParseAddrPort(b.Listener.Addr().String()), CertificatePEM: serverCert, KeyPEM: serverKey, TrustPEM: trust, UpstreamTLS: &edge.ManagementUpstreamTLS{ServerName: "management.test", TrustPEM: trust, CertificatePEM: clientCert, KeyPEM: clientKey}}}}
	authorization := &authority{old: plan, new: plan}
	supervisor := edge.NewSupervisor(process, disk, disk, nginx.Compiler{}, authorization)
	if _, e = supervisor.Apply(t.Context(), plan.Snapshot.Version); e != nil {
		t.Fatal(e)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "management.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:8443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := func(method string) (int, string) {
		t.Helper()
		r, _ := http.NewRequest(method, "https://management.test/", strings.NewReader("owned-write"))
		r.Header.Set("Cookie", "session=shared-session")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if code, body := request("GET"); code != 200 || body != "A:session=shared-session" {
		t.Fatal("local API not preferred", code, body)
	}
	if code, _ := request("POST"); code != 502 || writesA.Load() != 1 || writesB.Load() != 0 {
		t.Fatal("unknown-result POST replayed", code, writesA.Load(), writesB.Load())
	}
	// Maintenance is a validated native derived reload before stopping A.
	desired := plan
	desired.Runtime.Generation = "g2"
	management := *plan.Runtime.Management
	management.APIUnavailable = true
	desired.Runtime.Management = &management
	authorization.old = desired
	if result, e := supervisor.ApplyDerived(t.Context(), "management"); e != nil || result.Version != "management-peer/g2" {
		t.Fatal("maintenance native reload unconfirmed", result, e)
	}
	if code, body := request("GET"); code != 200 || body != "B:session=shared-session" {
		t.Fatal("excluded API still routed before stop", code, body)
	}
	// Re-admit the target in a separate generation, then inject an unexpected
	// connection failure to exercise safe connect-before-send fallback too.
	restored := plan
	restored.Runtime.Generation = "g3"
	authorization.old = restored
	if _, e := supervisor.ApplyDerived(t.Context(), "management"); e != nil {
		t.Fatal(e)
	}
	a.Close()
	time.Sleep(2100 * time.Millisecond)
	if code, body := request("POST"); code != 200 || body != "B:session=shared-session" || writesB.Load() != 1 {
		t.Fatal("connection failure did not safely fall back", code, body, writesB.Load())
	}
	b.Close()
	if code, _ := request("GET"); code != 502 {
		t.Fatal("both API failure unexpectedly served", code)
	}
	if actual, e := process.Observe(t.Context()); e != nil || actual != "management-peer/g3" {
		t.Fatal("API outage stopped data Nginx", actual, e)
	}
}
