//go:build native

package runtime_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeCorruptCurrentBootCannotRevivePreviousCRL(t *testing.T) {
	now := time.Now().UTC()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned CRL root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(raw)
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	leaf := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"entry.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		private, _ := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	serverCert, serverKey := leaf(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := leaf(99, x509.ExtKeyUsageClientAuth)
	makeCRL := func(number int64, revoked bool) []byte {
		r := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
		if revoked {
			r.ThisUpdate = now
			r.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: now.Add(-time.Second)}}
		}
		der, e := x509.CreateRevocationList(rand.Reader, r, ca, key)
		if e != nil {
			t.Fatal(e)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}
	root := filepath.Join(t.TempDir(), "runtime")
	disk, e := fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	plan := edge.Plan{Snapshot: app.Snapshot{Version: "native-crl", Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"entry.test"}, EntryCertificate: &app.MaterialRef{ID: "entry", Revision: 1}, ClientVerification: app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, Depth: 2, Revocation: "crl"}, Maintenance: app.MaintenancePolicy{Enabled: true, Status: 503, Message: "crl-allowed"}}}}}, Runtime: edge.RuntimeState{Now: now, Generation: "g1", LogDirectory: filepath.Join(root, "logs"), Materials: map[string]edge.Material{"entry": {VersionID: "entry-version", Revision: 1, CertificatePEM: serverCert, KeyPEM: serverKey}, "trust": {VersionID: "trust-version", Revision: 1, TrustPEM: trust, CRLPEM: makeCRL(1, false)}}}}
	process, e := nginx.NewProcess("/usr/sbin/nginx", root)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = process.Stop(t.Context()) }()
	apply := func() edge.BootBundle {
		artifact, e := (nginx.Compiler{}).Compile(plan.Snapshot, plan.Runtime)
		if e != nil {
			t.Fatal(e)
		}
		bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: plan.Snapshot.Version + "/" + plan.Runtime.Generation, Generation: plan.Runtime.Generation, AuthorizationID: plan.Snapshot.Version, CreatedAt: plan.Runtime.Now}, Plan: plan, Files: artifact.Files}
		if e = disk.StageConfirmed(t.Context(), bundle); e != nil {
			t.Fatal(e)
		}
		path, e := disk.Stage(t.Context(), artifact)
		if e != nil {
			t.Fatal(e)
		}
		if e = process.Validate(t.Context(), path); e != nil {
			t.Fatal(e)
		}
		if e = disk.Switch(t.Context(), artifact.ID); e != nil {
			t.Fatal(e)
		}
		if e = process.Activate(t.Context(), bundle.Manifest.Version); e != nil {
			t.Fatal(e)
		}
		if e = disk.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: artifact.ID, Version: bundle.Manifest.Version, Generation: plan.Runtime.Generation, VerifiedAt: time.Now().UTC()}); e != nil {
			t.Fatal(e)
		}
		return bundle
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(trust)
	pair, _ := tls.X509KeyPair(clientCert, clientKey)
	allowed := func() bool {
		transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "entry.test", Certificates: []tls.Certificate{pair}}}
		defer transport.CloseIdleConnections()
		c := &http.Client{Timeout: time.Second, Transport: transport}
		request, _ := http.NewRequest("GET", "https://127.0.0.1:8443/", nil)
		request.Host = "entry.test"
		r, e := c.Do(request)
		if e != nil {
			return false
		}
		defer r.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		return r.StatusCode == 503 && string(body) == "crl-allowed"
	}
	apply()
	if !allowed() {
		t.Fatal("initial client certificate not accepted")
	}
	material := plan.Runtime.Materials["trust"]
	material.CRLPEM = makeCRL(2, true)
	plan.Runtime.Materials["trust"] = material
	plan.Runtime.Generation = "g2"
	current := apply()
	if allowed() {
		t.Fatal("fresh native CRL did not deny revoked client")
	}
	oldPID := process.PID()
	if e = process.Stop(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "releases", current.Manifest.ArtifactID, "nginx.conf"), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	disk, e = fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	process, e = nginx.NewProcess("/usr/sbin/nginx", root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = edge.NewLocalBoot(process, disk, nginx.BootPolicy{}, time.Now).Start(t.Context(), node); e != nil {
		t.Fatal(e)
	}
	if process.PID() == oldPID || allowed() {
		t.Fatal("cold boot revived revoked client from previous signed CRL")
	}
	t.Log("real native CRL1 accepted client99, confirmed CRL2 revoked it; killed child and corrupted current config, retained minimum restricted previous bundle and cold native handshake stayed denied")
}
