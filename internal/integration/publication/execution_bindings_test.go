package publication

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func bindingPlan(t *testing.T) edge.Plan {
	t.Helper()
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned binding root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(der)
	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, root, key)
	if e != nil {
		t.Fatal(e)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"entry.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	ref := func(id string) *app.MaterialRef { return &app.MaterialRef{ID: id, Revision: 1} }
	target := func(id, client string) app.Target {
		return app.Target{ID: id, Revision: 1, Config: app.TargetConfig{Protocol: "https", TLSNameMode: "fixed", TLSName: "backend.test", Trust: ref("trust"), ClientCertificate: ref(client), AllowedNetworks: []string{"10.0.0.0/8"}, Members: []app.TargetMember{{Address: "10.0.0.9", Port: 443, Weight: 1}}}}
	}
	plan := edge.Plan{Snapshot: app.Snapshot{Version: "v1", Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"entry.test"}, EntryCertificate: ref("entry"), DefaultTarget: app.TargetRef{ID: "default"}}}}, Targets: []app.Target{target("default", "default-client"), target("route", "route-client")}}, Runtime: edge.RuntimeState{Generation: "g1", Now: now, Health: map[string]edge.Health{}, Materials: map[string]edge.Material{"trust": {Revision: 1, TrustPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), CRLPEM: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})}}}}
	for _, id := range []string{"entry", "default-client", "route-client", "disabled-entry"} {
		plan.Runtime.Materials[id] = edge.Material{Revision: 1, VersionID: "v-" + id, Digest: "digest-" + id, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	}
	return plan
}

func TestVerifiedBindingsFollowActualNativeCertificateDirectives(t *testing.T) {
	for _, scenario := range []string{"default-live", "root-prefix", "all-unhealthy", "shared-live-route", "disabled-maintenance"} {
		t.Run(scenario, func(t *testing.T) {
			plan := bindingPlan(t)
			want := []string{"default-client", "entry"}
			directives := 1
			switch scenario {
			case "root-prefix":
				plan.Snapshot.Sites[0].Config.Routes = []app.Route{{Match: "prefix", Path: "/", Target: app.TargetRef{ID: "route"}}}
				want = []string{"entry", "route-client"}
			case "all-unhealthy":
				plan.Runtime.Health["default"] = edge.Health{TargetRevision: 1, Unhealthy: map[string]bool{"10.0.0.9:443": true}}
				want = []string{"entry"}
				directives = 0
			case "shared-live-route":
				plan.Snapshot.Sites[0].Config.Routes = []app.Route{{Match: "prefix", Path: "/", Target: app.TargetRef{ID: "route"}}}
				plan.Runtime.Health["default"] = edge.Health{TargetRevision: 1, Unhealthy: map[string]bool{"10.0.0.9:443": true}}
				plan.Snapshot.Targets[1].Config.ClientCertificate = &app.MaterialRef{ID: "default-client", Revision: 1}
			case "disabled-maintenance":
				plan.Snapshot.Sites[0].Config.Maintenance = app.MaintenancePolicy{Enabled: true, Status: 503, Message: "owned"}
				disabled := plan.Snapshot.Sites[0]
				disabled.ID = "disabled"
				disabled.Config.Enabled = false
				disabled.Config.EntryCertificate = &app.MaterialRef{ID: "disabled-entry", Revision: 1}
				plan.Snapshot.Sites = append(plan.Snapshot.Sites, disabled)
				// Maintenance still emits/loads location TLS directives.
				want = []string{"default-client", "entry"}
				directives = 1
			}
			artifact, e := (nginx.Compiler{}).Compile(plan.Snapshot, plan.Runtime)
			if e != nil {
				t.Fatal(e)
			}
			got := verifiedBindings(plan, artifact)
			ids := []string{}
			for _, v := range got {
				ids = append(ids, v.ID)
				if v.VersionID != "v-"+v.ID || v.Revision != 1 || v.Kind != "certificate" {
					t.Fatal("immutable owner metadata changed", v)
				}
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("native output/receipt mismatch: got %v want %v", ids, want)
			}
			if strings.Count(string(artifact.Files["nginx.conf"]), "proxy_ssl_certificate ") != directives {
				t.Fatal("scenario did not exercise native client TLS directive branch")
			}
			// Receipt values must not alias the compiler-owned immutable selection.
			if len(got) > 0 {
				got[0].ID = "changed"
				if artifact.CertificateRefs[0].ID == "changed" {
					t.Fatal("selection slice aliased")
				}
			}
		})
	}
}

// A compiler cannot substitute/alias selected refs while retaining the same
// native content digest. Final authority compares both immutable identities.
type aliasingSelectionCompiler struct {
	refs  []app.Material
	calls int
}

func (c *aliasingSelectionCompiler) Compile(app.Snapshot, edge.RuntimeState) (edge.Artifact, error) {
	c.calls++
	if c.calls == 2 {
		c.refs[0].ID = "substituted"
	}
	return edge.Artifact{Digest: "same-native-bytes", CertificateRefs: c.refs}, nil
}
func TestSameArtifactRejectsChangedSelectionDespiteEqualContentDigest(t *testing.T) {
	compiler := &aliasingSelectionCompiler{refs: []app.Material{{Kind: "certificate", ID: "staged", Revision: 1}}}
	execution := &Execution{compiler: compiler}
	if _, e := execution.sameArtifact(edge.Plan{}, edge.Plan{}); e == nil {
		t.Fatal("aliased/substituted selected certificate refs accepted under unchanged digest")
	}
}
