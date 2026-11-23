package nginx_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	storefs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootClockAndMaterialExpiry(t *testing.T) {
	s, r, ca, key := revocationFixture(t)
	leaf := func(name string, serial int64, until time.Time) edge.Material {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{name}, NotBefore: r.Now.Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		kb, _ := x509.MarshalPKCS8PrivateKey(k)
		return edge.Material{VersionID: name, Revision: 1, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})}
	}
	r.Materials["entry"] = leaf("entry.test", 2, r.Now.Add(10*time.Minute))
	r.Materials["healthy"] = leaf("healthy.test", 3, r.Now.Add(time.Hour))
	good := s.Sites[0]
	good.ID = "healthy"
	good.Config.Domains = []string{"healthy.test"}
	good.Config.EntryCertificate = &app.MaterialRef{ID: "healthy", Revision: 1}
	s.Sites = append(s.Sites, good)
	artifact, err := (nginx.Compiler{}).Compile(s, r)
	if err != nil {
		t.Fatal(err)
	}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "v1/g1", Generation: "g1", AuthorizationID: "v1", CreatedAt: r.Now}, Files: artifact.Files, Plan: edge.Plan{Snapshot: s, Runtime: r}, VerifiedAt: r.Now, CurrentFloor: domain.SecurityFloor{Node: node, RecordedAt: r.Now}}
	policy := nginx.BootPolicy{}
	if _, err = policy.Prepare(t.Context(), bundle, r.Now.Add(-time.Second)); err == nil {
		t.Fatal("clock rollback extended material lifetime")
	}
	for _, scenario := range []string{"expiry", "revocation"} {
		t.Run(scenario, func(t *testing.T) {
			b := bundle
			now := r.Now.Add(20 * time.Minute)
			if scenario == "revocation" {
				now = r.Now.Add(time.Second)
				b.CurrentFloor.Sequence = 1
				b.CurrentFloor.RevokedMaterialIDs = []string{"entry.test"}
			}
			got, err := policy.Prepare(t.Context(), b, now)
			if err != nil {
				t.Fatal(err)
			}
			config := string(got.Files["nginx.conf"])
			if strings.Contains(config, "server_name entry.test") || !strings.Contains(config, "server_name healthy.test") {
				t.Fatal("unsafe site retained or healthy site lost")
			}
			if !strings.Contains(string(bundle.Files["nginx.conf"]), "server_name entry.test") || len(bundle.Plan.Snapshot.Sites) != 2 {
				t.Fatal("policy mutated confirmed source")
			}
		})
	}
}

func TestOfflineOCSPUsesSignedCacheFreshnessInsteadOfOldReadinessProbe(t *testing.T) {
	s, r, _, _ := revocationFixture(t)
	initial := r.Now
	s.Sites[0].Config.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, Depth: 2, Revocation: "ocsp"}
	material := r.Materials["trust"]
	material.OCSP = &edge.OCSPState{Generation: "status-g1", ValidUntil: initial.Add(time.Second), ResponderNames: []string{"ocsp.internal.test"}}
	r.Materials["trust"] = material
	r.OCSPResolver = &edge.ResolverState{Generation: "resolver-g1", Servers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:5353")}, TimeoutSeconds: 1, ValidForSeconds: 30}
	r.TLSHandshakeTimeoutSeconds = 5
	r.OCSPResponder = "http://127.0.0.1:9091/ocsp"
	artifact, err := (nginx.Compiler{}).Compile(s, r)
	if err != nil {
		t.Fatal(err)
	}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	bundle := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: artifact.ID, Version: "v1/g1", Generation: "g1", AuthorizationID: "v1", CreatedAt: initial}, Files: artifact.Files, Plan: edge.Plan{Snapshot: s, Runtime: r}, VerifiedAt: initial, CurrentFloor: domain.SecurityFloor{Node: node, RecordedAt: initial}}
	got, err := (nginx.BootPolicy{}).Prepare(t.Context(), bundle, initial.Add(time.Minute))
	if err != nil || !strings.Contains(string(got.Files["nginx.conf"]), "server_name entry.test") {
		t.Fatalf("old synthetic readiness disabled independently validated signed cache: %v", err)
	}
}

func TestReviewNewCRLDoesNotPermitPreviousCRLRollback(t *testing.T) {
	s, r, ca, key := revocationFixture(t)
	s.Sites[0].Config.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, Depth: 2, Revocation: "crl"}
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	disk, e := storefs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	stage := func() edge.BootBundle {
		a, e := (nginx.Compiler{}).Compile(s, r)
		if e != nil {
			t.Fatal(e)
		}
		b := edge.BootBundle{Manifest: domain.BootManifest{Format: 1, Node: node, ArtifactID: a.ID, Version: s.Version + "/" + r.Generation, Generation: r.Generation, AuthorizationID: s.Version, CreatedAt: r.Now}, Files: a.Files, Plan: edge.Plan{Snapshot: s, Runtime: r}}
		if e = disk.StageConfirmed(t.Context(), b); e != nil {
			t.Fatal(e)
		}
		if e = disk.Confirm(t.Context(), edge.BootEvidence{Node: node, ArtifactID: a.ID, Version: b.Manifest.Version, Generation: r.Generation, VerifiedAt: r.Now}); e != nil {
			t.Fatal(e)
		}
		return b
	}
	first := stage()
	newer, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: r.Now.Add(-time.Second), NextUpdate: r.Now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: r.Now.Add(-time.Second)}}}, ca, key)
	if e != nil {
		t.Fatal(e)
	}
	m := r.Materials["trust"]
	m.CRLPEM = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: newer})
	r.Materials["trust"] = m
	r.Generation = "g2"
	second := stage()
	if e = os.WriteFile(filepath.Join(root, "releases", second.Manifest.ArtifactID, "nginx.conf"), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	recovered, e := disk.LoadConfirmed(t.Context(), node)
	if e != nil {
		return
	}
	prepared, e := (nginx.BootPolicy{}).Prepare(t.Context(), recovered, r.Now.Add(time.Second))
	if e != nil {
		return
	}
	if prepared.Manifest.ArtifactID == first.Manifest.ArtifactID && len(prepared.Plan.Snapshot.Sites) > 0 {
		t.Fatal("new CRL with revoked serial 99 was confirmed, but damaged current boot accepts prior CRL without serial 99")
	}
}
