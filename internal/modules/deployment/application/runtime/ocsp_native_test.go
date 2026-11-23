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
	certcache "gatebeam/internal/modules/certificates/application/statuscache"
	"gatebeam/internal/modules/certificates/infrastructure/ocspcache"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"golang.org/x/crypto/ocsp"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineOCSPNativeColdRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline cache CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(issuerDER)
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	leaf := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte, *x509.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"entry.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, OCSPServer: []string{"http://unavailable.invalid/ocsp"}}
		der, e := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
		if e != nil {
			t.Fatal(e)
		}
		kb, _ := x509.MarshalPKCS8PrivateKey(key)
		parsed, _ := x509.ParseCertificate(der)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), parsed
	}
	serverCert, serverKey, _ := leaf(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey, clientLeaf := leaf(3, x509.ExtKeyUsageClientAuth)
	request, err := ocsp.CreateRequest(clientLeaf, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	good, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{SerialNumber: clientLeaf.SerialNumber, Status: ocsp.Good, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(30 * time.Minute)}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "runtime")
	disk, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	cacheRoot := filepath.Join(root, "ocsp-cache")
	startCache := func(seed bool) (*certcache.Service, func()) {
		store, e := ocspcache.NewStore(cacheRoot)
		if e != nil {
			t.Fatal(e)
		}
		verifier, e := ocspcache.NewVerifier([][]byte{issuer.Raw})
		if e != nil {
			t.Fatal(e)
		}
		service, e := certcache.New(store, verifier, nil)
		if e != nil {
			t.Fatal(e)
		}
		if seed {
			if e = service.Observe(t.Context(), certcache.Request{DER: request}, good, time.Now().UTC()); e != nil {
				t.Fatal(e)
			}
		}
		listener, e := net.Listen("tcp", "127.0.0.1:9091")
		if e != nil {
			t.Fatal(e)
		}
		server := &http.Server{Handler: ocspcache.Handler(service), ReadHeaderTimeout: time.Second}
		go func() { _ = server.Serve(listener) }()
		return service, func() { _ = server.Close() }
	}
	_, stopCache := startCache(true)
	t.Cleanup(func() { stopCache() })
	plan := edge.Plan{Snapshot: app.Snapshot{Version: "offline-ocsp", Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"entry.test"}, EntryCertificate: &app.MaterialRef{ID: "entry", Revision: 1}, ClientVerification: app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, Depth: 2, Revocation: "ocsp"}, Maintenance: app.MaintenancePolicy{Enabled: true, Status: 503, Message: "cached-mtls"}}}}}, Runtime: edge.RuntimeState{Generation: "g1", Now: time.Now().UTC(), LogDirectory: filepath.Join(root, "logs"), OCSPResponder: "http://127.0.0.1:9091/ocsp", TLSHandshakeTimeoutSeconds: 5, OCSPResolver: &edge.ResolverState{Generation: "g1", Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:5353")}, TimeoutSeconds: 1, ValidForSeconds: 30}, Materials: map[string]edge.Material{"entry": {VersionID: "entry-version", Revision: 1, CertificatePEM: serverCert, KeyPEM: serverKey}, "trust": {VersionID: "trust-version", Revision: 1, TrustPEM: issuerPEM, OCSP: &edge.OCSPState{Generation: "g1", ValidUntil: now.Add(time.Hour), ResponderNames: []string{"unavailable.invalid"}}}}}}
	process, err := nginx.NewProcess("/usr/sbin/nginx", root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Stop(context.Background()) })
	supervisor := edge.NewSupervisor(process, disk, disk, nginx.Compiler{}, &authority{old: plan, new: plan})
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	supervisor.SetBootStore(disk, node)
	if _, err = supervisor.Apply(t.Context(), "offline-ocsp"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func() bool {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "entry.test", Certificates: []tls.Certificate{clientPair}}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:8443/", nil)
		req.Host = "entry.test"
		resp, e := client.Do(req)
		if e != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return resp.StatusCode == 503 && string(body) == "cached-mtls"
	}
	if !fetch() {
		t.Fatal("native client OCSP failed with fresh cached original DER")
	}
	oldPID := process.PID()
	if err = process.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	stopCache()
	service, closeCache := startCache(false)
	stopCache = closeCache
	process, err = nginx.NewProcess("/usr/sbin/nginx", root)
	if err != nil {
		t.Fatal(err)
	}
	local := edge.NewLocalBoot(process, disk, nginx.BootPolicy{}, time.Now)
	if _, err = local.Start(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	if process.PID() == oldPID || !fetch() {
		t.Fatal("cold Nginx/cache restart relied on old worker memory or live CA")
	}
	revoked, e := ocsp.CreateResponse(issuer, issuer, ocsp.Response{SerialNumber: clientLeaf.SerialNumber, Status: ocsp.Revoked, RevokedAt: now, ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, issuerKey)
	if e != nil {
		t.Fatal(e)
	}
	if err = service.Observe(t.Context(), certcache.Request{DER: request}, revoked, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if fetch() {
		t.Fatal("native mTLS accepted known revoked client")
	}
	t.Logf("native child %d replaced by %d; CA unreachable, persisted signed DER verified; known revocation denied", oldPID, process.PID())
}
