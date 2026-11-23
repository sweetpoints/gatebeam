package nginx_test

import (
	"bytes"
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
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestEmptyDeterministicArtifact(t *testing.T) {
	c := nginx.Compiler{}
	a, e := c.Compile(app.Snapshot{Version: "v1"}, edge.RuntimeState{Generation: "g1"})
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Compile(app.Snapshot{Version: "v1"}, edge.RuntimeState{Generation: "g1"})
	if e != nil || a.Digest != b.Digest || !bytes.Equal(a.Files["nginx.conf"], b.Files["nginx.conf"]) {
		t.Fatal("nondeterministic artifact", e)
	}
	if bytes.Contains(a.Files["nginx.conf"], []byte("listen 9090;")) {
		t.Fatal("public probe")
	}
}
func TestCompilerRejectsInjectionAmbiguityAndStaleResolution(t *testing.T) {
	s := app.Snapshot{Version: "v1", Targets: []app.Target{{ID: "t", Revision: 1, Config: app.TargetConfig{Protocol: "http", AllowedNetworks: []string{"10.0.0.0/8"}, Members: []app.TargetMember{{Address: "backend.internal", Port: 80, Weight: 1}}}}}}
	r := edge.RuntimeState{Generation: "g1", Resolved: map[string]edge.Resolution{"t/backend.internal": {TargetRevision: 1, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}}}}
	if _, e := (nginx.Compiler{}).Compile(s, r); e != nil {
		t.Fatal(e)
	}
	stale := r
	stale.Resolved = map[string]edge.Resolution{"t/backend.internal": {TargetRevision: 2, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.9")}}}
	if _, e := (nginx.Compiler{}).Compile(s, stale); e == nil {
		t.Fatal("stale resolution accepted")
	}
	s.Targets[0].Config.Members = append(s.Targets[0].Config.Members, app.TargetMember{Address: "10.0.0.9", Port: 80, Weight: 1})
	if _, e := (nginx.Compiler{}).Compile(s, r); e == nil {
		t.Fatal("ambiguous endpoint accepted")
	}
	for _, path := range []string{"/;return 200;", "/${host}", "/\"{}", "/a\\b", "/\n"} {
		snapshot := app.Snapshot{Version: "v1", Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"a.test"}, Routes: []app.Route{{Match: "prefix", Path: path}}}}}}
		if _, e := (nginx.Compiler{}).Compile(snapshot, edge.RuntimeState{Generation: "g1"}); e == nil {
			t.Fatalf("path injection accepted %q", path)
		}
	}
}
func TestDisabledExcludedAndNoDraftCFTrust(t *testing.T) {
	s := app.Snapshot{Version: "v1", Sites: []app.Site{{ID: "disabled", Revision: 1, Config: app.SiteConfig{Domains: []string{"disabled.test"}}}, {ID: "enabled", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"enabled.test"}, Cloudflare: app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{"0.0.0.0/0"}}}}}}
	if _, e := (nginx.Compiler{}).Compile(s, edge.RuntimeState{Generation: "g1"}); e == nil {
		t.Fatal("missing official CF set accepted")
	}
	s.Sites = s.Sites[:1]
	a, e := (nginx.Compiler{}).Compile(s, edge.RuntimeState{Generation: "g1"})
	if e != nil || bytes.Contains(a.Files["nginx.conf"], []byte("disabled.test")) {
		t.Fatal("disabled site entry emitted", e)
	}
}
func TestProtectedControlTargetCannotBeAuthorizedByUserCIDR(t *testing.T) {
	s := app.Snapshot{Version: "v1", Targets: []app.Target{{ID: "t", Revision: 1, Config: app.TargetConfig{Protocol: "http", AllowedNetworks: []string{"10.0.0.0/8"}, Members: []app.TargetMember{{Address: "10.0.0.1", Port: 8080, Weight: 1}}}}}}
	r := edge.RuntimeState{Generation: "g1", ProtectedNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}
	if _, e := (nginx.Compiler{}).Compile(s, r); e == nil {
		t.Fatal("control target accepted")
	}
}

func TestGCPMetadataLiteralCannotBeAuthorizedByUserCIDR(t *testing.T) {
	s := app.Snapshot{Version: "v1", Targets: []app.Target{{ID: "t", Revision: 1, Config: app.TargetConfig{Protocol: "http", AllowedNetworks: []string{"fc00::/7"}, Members: []app.TargetMember{{Address: "fd20:ce::254", Port: 80, Weight: 1}}}}}}
	if _, e := (nginx.Compiler{}).Compile(s, edge.RuntimeState{Generation: "g1"}); e == nil {
		t.Fatal("compiler accepted GCP IPv6 metadata literal")
	}
}

func revocationFixture(t *testing.T) (app.Snapshot, edge.RuntimeState, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(der)
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, ca, key)
	if e != nil {
		t.Fatal(e)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"entry.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	leafKeyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	r := edge.RuntimeState{Generation: "g1", Now: now, Materials: map[string]edge.Material{"trust": {Revision: 1, TrustPEM: trust, CRLPEM: pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})}, "entry": {Revision: 1, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})}}}
	s := app.Snapshot{Version: "v1", Targets: []app.Target{{ID: "target", Revision: 1, Config: app.TargetConfig{Protocol: "https", TLSNameMode: "fixed", TLSName: "backend.test", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, AllowedNetworks: []string{"10.0.0.0/8"}, Members: []app.TargetMember{{Address: "10.0.0.9", Port: 443, Weight: 1}}}}}, Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"entry.test"}, DefaultTarget: app.TargetRef{ID: "target"}, EntryCertificate: &app.MaterialRef{ID: "entry", Revision: 1}}}}}
	return s, r, ca, key
}
func TestUpstreamCRLRequiredValidatedAndImmutable(t *testing.T) {
	s, r, ca, key := revocationFixture(t)
	a, e := (nginx.Compiler{}).Compile(s, r)
	if e != nil || !bytes.Contains(a.Files["nginx.conf"], []byte("proxy_ssl_crl materials/")) {
		t.Fatal("missing required CRL", e)
	}
	m := r.Materials["trust"]
	original := append([]byte{}, m.CRLPEM...)
	for _, kind := range []string{"missing", "invalid", "expired", "future", "wrong-signature", "non-ca-trust-entry"} {
		t.Run(kind, func(t *testing.T) {
			v := m
			switch kind {
			case "missing":
				v.CRLPEM = nil
			case "invalid":
				v.CRLPEM = []byte("invalid")
			case "expired", "future":
				list := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: r.Now.Add(-2 * time.Hour), NextUpdate: r.Now.Add(-time.Hour)}
				if kind == "future" {
					list.ThisUpdate = r.Now.Add(time.Minute)
					list.NextUpdate = r.Now.Add(time.Hour)
				}
				der, e := x509.CreateRevocationList(rand.Reader, list, ca, key)
				if e != nil {
					t.Fatal(e)
				}
				v.CRLPEM = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
			case "wrong-signature":
				block, _ := pem.Decode(v.CRLPEM)
				block.Bytes[len(block.Bytes)-1] ^= 1
				v.CRLPEM = pem.EncodeToMemory(block)
			case "non-ca-trust-entry":
				v.TrustPEM = append(append([]byte{}, v.TrustPEM...), r.Materials["entry"].CertificatePEM...)
			}
			r.Materials["trust"] = v
			if _, e := (nginx.Compiler{}).Compile(s, r); e == nil {
				t.Fatal("invalid required revocation state accepted")
			}
		})
	}
	r.Materials["trust"] = m
	m.CRLPEM[0] ^= 1
	found := false
	for name, data := range a.Files {
		if strings.HasSuffix(name, ".crl") {
			found = true
			if !bytes.Equal(data, original) {
				t.Fatal("artifact CRL aliases runtime bytes")
			}
		}
	}
	if !found {
		t.Fatal("CRL file missing")
	}
}
func TestOCSPRequiresBoundedTrustedResolverAndCurrentState(t *testing.T) {
	s, r, _, _ := revocationFixture(t)
	s.Sites[0].Config.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, Depth: 2, Revocation: "ocsp"}
	m := r.Materials["trust"]
	m.OCSP = &edge.OCSPState{Generation: "ocsp-1", ValidUntil: r.Now.Add(time.Minute), ResponderNames: []string{"ocsp.internal.test"}}
	r.Materials["trust"] = m
	r.OCSPResolver = &edge.ResolverState{Generation: "dns-1", Servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.53:53")}, TimeoutSeconds: 1, ValidForSeconds: 30}
	r.TLSHandshakeTimeoutSeconds = 2
	a, e := (nginx.Compiler{}).Compile(s, r)
	if e != nil {
		t.Fatal(e)
	}
	for _, directive := range []string{"ssl_ocsp on;", "resolver 10.0.0.53:53 valid=30s;", "resolver_timeout 1s;", "client_header_timeout 2s;"} {
		if !bytes.Contains(a.Files["nginx.conf"], []byte(directive)) {
			t.Fatal("missing", directive)
		}
	}
	for _, kind := range []string{"missing-resolver", "missing-state", "stale-state", "bad-name", "unbounded-dns", "unbounded-handshake"} {
		t.Run(kind, func(t *testing.T) {
			state := r
			material := m
			policy := *m.OCSP
			material.OCSP = &policy
			resolver := *r.OCSPResolver
			state.OCSPResolver = &resolver
			state.Materials = map[string]edge.Material{}
			for k, v := range r.Materials {
				state.Materials[k] = v
			}
			switch kind {
			case "missing-resolver":
				state.OCSPResolver = nil
			case "missing-state":
				material.OCSP = nil
			case "stale-state":
				material.OCSP.ValidUntil = r.Now
			case "bad-name":
				material.OCSP.ResponderNames = []string{"ocsp.internal;return 200;"}
			case "unbounded-dns":
				state.OCSPResolver.TimeoutSeconds = 0
			case "unbounded-handshake":
				state.TLSHandshakeTimeoutSeconds = 0
			}
			state.Materials["trust"] = material
			if _, e := (nginx.Compiler{}).Compile(s, state); e == nil {
				t.Fatal("invalid required OCSP state accepted")
			}
		})
	}
}

func TestOCSPArtifactDoesNotRetainRuntimeSlices(t *testing.T) {
	s, r, _, _ := revocationFixture(t)
	s.Sites[0].Config.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, Depth: 2, Revocation: "ocsp"}
	m := r.Materials["trust"]
	m.OCSP = &edge.OCSPState{Generation: "ocsp-1", ValidUntil: r.Now.Add(time.Minute), ResponderNames: []string{"ocsp.internal.test"}}
	r.Materials["trust"] = m
	r.OCSPResolver = &edge.ResolverState{Generation: "dns-1", Servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.53:53")}, TimeoutSeconds: 1, ValidForSeconds: 30}
	r.TLSHandshakeTimeoutSeconds = 2
	a, e := (nginx.Compiler{}).Compile(s, r)
	if e != nil {
		t.Fatal(e)
	}
	original := append([]byte{}, a.Files["nginx.conf"]...)
	r.OCSPResolver.Servers[0] = netip.MustParseAddrPort("10.0.0.54:5353")
	m.OCSP.ResponderNames[0] = "changed.internal.test"
	if !bytes.Equal(original, a.Files["nginx.conf"]) {
		t.Fatal("artifact retained mutable runtime OCSP/resolver slices")
	}
}

func TestControlledPersistentLogsContainStableSafeDimensions(t *testing.T) {
	a, e := (nginx.Compiler{}).Compile(app.Snapshot{Version: "v1"}, edge.RuntimeState{Generation: "g1"})
	if e != nil {
		t.Fatal(e)
	}
	s := string(a.Files["nginx.conf"])
	for _, v := range []string{`"site_id"`, `"request_id"`, `"time"`, `"method"`, `"path_pattern"`, `"route"`, `"request_time"`, `"target_id"`, `access_log /tmp/access.log edge;`} {
		if !strings.Contains(s, v) {
			t.Errorf("missing persistent dimension: %s", v)
		}
	}
	for _, secret := range []string{"$request_uri", "$args", "$http_authorization", "$request_body", `"path":"$uri"`, "$upstream_addr", "$http_cookie"} {
		if strings.Contains(s, secret) {
			t.Errorf("unsafe log field %s", secret)
		}
	}
}

func TestManagementBootstrapValidatesOwnedTLSAndFixedAPI(t *testing.T) {
	_, r, _, _ := revocationFixture(t)
	m := r.Materials["entry"]
	r.Management = &edge.ManagementTLS{Domain: "entry.test", APIAddress: netip.MustParseAddrPort("172.30.0.3:8080"), CertificatePEM: m.CertificatePEM, KeyPEM: m.KeyPEM, TrustPEM: r.Materials["trust"].TrustPEM}
	a, e := (nginx.Compiler{}).Compile(app.Snapshot{Version: "bootstrap"}, r)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(a.Files["nginx.conf"]), "proxy_pass http://172.30.0.3:8080;") || !strings.Contains(string(a.Files["nginx.conf"]), "/_gatebeam/ready") {
		t.Fatal("management TLS route missing")
	}
	r.Management.Domain = "wrong.test"
	if _, e = (nginx.Compiler{}).Compile(app.Snapshot{Version: "bootstrap"}, r); e == nil {
		t.Fatal("management name mismatch accepted")
	}
	r.Management.Domain = "entry.test"
	r.Management.TrustPEM = nil
	if _, e = (nginx.Compiler{}).Compile(app.Snapshot{Version: "bootstrap"}, r); e == nil {
		t.Fatal("untrusted bootstrap accepted")
	}
}

func TestManagementPeerFallbackDoesNotReplayWrites(t *testing.T) {
	_, r, ca, caKey := revocationFixture(t)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: r.Now.Add(-time.Hour), NotAfter: r.Now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, template, ca, &clientKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	client := edge.Material{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})}
	m := r.Materials["entry"]
	r.Management = &edge.ManagementTLS{Domain: "entry.test", APIAddress: netip.MustParseAddrPort("172.30.0.3:8444"), PeerAPIAddress: netip.MustParseAddrPort("172.30.0.4:8444"), CertificatePEM: m.CertificatePEM, KeyPEM: m.KeyPEM, TrustPEM: r.Materials["trust"].TrustPEM, UpstreamTLS: &edge.ManagementUpstreamTLS{ServerName: "entry.test", TrustPEM: r.Materials["trust"].TrustPEM, CertificatePEM: client.CertificatePEM, KeyPEM: client.KeyPEM}}
	a, e := (nginx.Compiler{}).Compile(app.Snapshot{Version: "peer"}, r)
	if e != nil {
		t.Fatal(e)
	}
	conf := string(a.Files["nginx.conf"])
	for _, expected := range []string{"server 172.30.0.3:8444", "server 172.30.0.4:8444 backup", "proxy_next_upstream error timeout;", "proxy_next_upstream_tries 2;", "proxy_ssl_verify on;", "proxy_ssl_server_name on;", "proxy_pass https://gatebeam_management;"} {
		if !strings.Contains(conf, expected) {
			t.Fatalf("missing management behavior %s", expected)
		}
	}
	if strings.Contains(conf, "non_idempotent") {
		t.Fatal("unknown write replay enabled")
	}
	r.Management.APIUnavailable = true
	a, e = (nginx.Compiler{}).Compile(app.Snapshot{Version: "peer"}, r)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(a.Files["nginx.conf"]), "server 172.30.0.3:8444") {
		t.Fatal("maintenance target still routed")
	}
	r.Management.PeerUnavailable = true
	a, e = (nginx.Compiler{}).Compile(app.Snapshot{Version: "peer"}, r)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(a.Files["nginx.conf"]), "return 503;") {
		t.Fatal("both maintenance APIs silently routed")
	}
}
