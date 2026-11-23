//go:build integration

package pki_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"filippo.io/age"
	"fmt"
	"gatebeam/internal/integration/certificatematerials"
	certapp "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	"gatebeam/internal/modules/certificates/infrastructure/httpchallenge"
	certlego "gatebeam/internal/modules/certificates/infrastructure/lego"
	certrepo "gatebeam/internal/modules/certificates/infrastructure/postgres"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	deployrepo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/deployment/infrastructure/probe"
	"gatebeam/internal/modules/pki"
	management "gatebeam/internal/modules/pki/application"
	statusapp "gatebeam/internal/modules/pki/application/status"
	pkidomain "gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	pkirepo "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ocsp"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDedicatedClientDirectoryWithUnmodifiedLego(t *testing.T) { nativeACMEFixture(t, true) }

func verifyBusinessMTLS(t *testing.T, addresses map[string]string, roots *x509.CertPool) {
	t.Helper()
	for name, address := range addresses {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name + ".internal.test"}}
		client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
		response, err := client.Get("https://" + address + "/")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				t.Fatal("business Nginx admitted request without gateway client identity")
			}
		}
		tr.CloseIdleConnections()
	}
}

// These application ports are fixture authorization/graph adapters only. Signing
// still crosses the actual TLS ACME transport into the separately running CA.
type identitySecurity struct{ tx transaction.Runner }

func (s identitySecurity) Within(ctx context.Context, _ certapp.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}
func (identitySecurity) RequireWithin(transaction.Scope, certapp.ActorRef, []string) error {
	return nil
}

type identityGraph struct{}

func (identityGraph) GuardWithin(transaction.Scope) error { return nil }

// Fixture node authority is local to this isolated lab. Production uses the
// protected deployment registry and per-node database principals.
type replicatedHTTPNodes struct{ refs []certapp.NodeRef }

func (n replicatedHTTPNodes) TargetsWithin(transaction.Scope) ([]certapp.NodeRef, error) {
	return n.refs, nil
}
func (n replicatedHTTPNodes) CallerWithin(_ transaction.Scope, ref certapp.NodeRef) error {
	for _, n := range n.refs {
		if n == ref {
			return nil
		}
	}
	return certapp.ErrChallenge
}

func clientIdentityClosure(t *testing.T, db *pgxpool.Pool, hc *http.Client, roots *x509.CertPool, rootPEM []byte, lab, online string, eab management.EABCredentials, addresses, containers map[string]string, ca string, start func(string, string, ...string) string) {
	t.Helper()
	// This is the whole owned test coordinator (ACME setup, multiple containers,
	// positive/negative mTLS probes and revocation). Each real HTTP operation,
	// route verifier and revocation observation keeps its own original bound.
	budget := 25 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		budget *= 12
	}
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	web := filepath.Join(lab, "web")
	if err := os.Mkdir(web, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(lab, "lego.conf"), []byte("events {} http { access_log off; server { listen 80; server_name lego.internal.test; root /web; } }"))
	start("lego", "lego.internal.test", "-v", filepath.Join(lab, "lego.conf")+":/lab/lego.conf:ro", "-v", web+":/web:ro", "--entrypoint", "nginx", nginxImage, "-c", "/lab/lego.conf", "-g", "daemon off;")
	providerID, _ := age.GenerateX25519Identity()
	leafID, _ := age.GenerateX25519Identity()
	providerPath, leafPath := filepath.Join(lab, "provider.key"), filepath.Join(lab, "leaf.key")
	write(t, providerPath, []byte(providerID.String()))
	write(t, leafPath, []byte(leafID.String()))
	provider, err := secrets.New(providerPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := secrets.New(leafPath)
	if err != nil {
		t.Fatal(err)
	}
	providerPublic, _ := secrets.NewRecipient(provider.Recipient())
	leafPublic, _ := secrets.NewRecipient(leaf.Recipient())
	tx := postgres.NewRunner(db)
	manager := certapp.NewManagement(identitySecurity{tx}, identityGraph{}, certrepo.New(), certcrypto.Crypto{}, leafPublic, providerPublic, audit.New())
	trust, err := manager.SaveTrust(ctx, certapp.ActorRef{}, "", 0, certapp.TrustBundle{Purpose: "clientAuth"}, rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	account, err := manager.SaveAccount(ctx, certapp.ActorRef{}, "", 0, certapp.ProviderAccount{Provider: "internal-client", Email: "ops@example.test", EABKeyID: eab.KeyID}, []byte(eab.HMAC))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := manager.SaveSpec(ctx, certapp.ActorRef{}, "", 0, certapp.Spec{Names: []string{"lego.internal.test"}, Purpose: "clientAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01", TrustID: trust.ID, TrustRevision: trust.Revision})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the product's coordinated HTTP-01 adapter with the unmodified
	// standard ACME client and actual port80 Nginx listeners on separate webroots.
	peerWeb := filepath.Join(lab, "web-peer")
	if err = os.MkdirAll(peerWeb, 0755); err != nil {
		t.Fatal(err)
	}
	start("lego-peer", "lego.internal.test", "-v", filepath.Join(lab, "lego.conf")+":/lab/lego.conf:ro", "-v", peerWeb+":/web:ro", "--entrypoint", "nginx", nginxImage, "-c", "/lab/lego.conf", "-g", "daemon off;")
	challengeNodes := replicatedHTTPNodes{refs: []certapp.NodeRef{{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, {ID: "22222222-2222-4222-8222-222222222222", Epoch: 1}}}
	coordinated := certapp.NewHTTPChallenges(tx, certrepo.NewHTTPChallenges(), challengeNodes)
	challengeFiles := make([]certapp.HTTPChallengeFiles, 2)
	for i, root := range []string{web, peerWeb} {
		resolved, e := filepath.EvalSymlinks(root)
		if e != nil {
			t.Fatal(e)
		}
		challengeFiles[i], e = httpchallenge.New(resolved)
		if e != nil {
			t.Fatal(e)
		}
	}
	syncCtx, stopSync := context.WithCancel(ctx)
	defer stopSync()
	syncDone := make(chan struct{})
	defer func() { stopSync(); <-syncDone }()
	syncErrors := make(chan error, 1)
	go func() {
		defer close(syncDone)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-syncCtx.Done():
				return
			case <-tick.C:
			}
			for i, node := range challengeNodes.refs {
				if e := coordinated.Sync(syncCtx, node, challengeFiles[i]); e != nil && syncCtx.Err() == nil {
					select {
					case syncErrors <- e:
					default:
					}
					return
				}
			}
		}
	}()
	worker := certapp.New(tx, certrepo.New(), identityGraph{}, certcrypto.Crypto{}, sealFixture{leafPublic}, &certlego.Client{Secrets: provider, WebRoot: web, HTTPChallenges: coordinated, HTTPClient: hc, InternalOrigin: "https://ca.internal.test:8443"}, jobs.New(db))
	version, err := worker.Ensure(ctx, spec.ID)
	if err != nil {
		select {
		case syncErr := <-syncErrors:
			t.Fatal("replicated HTTP01 sync", syncErr)
		default:
		}
		t.Fatal("worker ACME client identity", err)
	}
	edgeService := certapp.New(tx, certrepo.NewMaterialReader(), identityGraph{}, certcrypto.Crypto{}, leaf, nil, nil)
	edgeService.SetLeafStatus(certificatematerials.LeafStatus{Owner: statusapp.NewMaterials(pkirepo.New())})
	var material certapp.Materials
	err = tx.Within(ctx, func(sc transaction.Scope) error {
		var e error
		material, e = edgeService.ReadMaterialsWithin(sc, []certapp.MaterialRef{{ID: spec.ID, Kind: "certificate", Revision: spec.Revision, Purpose: "clientAuth"}})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := material.Items[0]
	block, _ := pem.Decode(identity.CertificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("client-only EKU", err)
	}
	if len(certificate.OCSPServer) != 1 || certificate.OCSPServer[0] != "http://ca.internal.test:8080/ocsp" {
		t.Fatal("actual standard-ACME client leaf lacks native business OCSP AIA", certificate.OCSPServer)
	}
	if version.ID != identity.Version.ID {
		t.Fatal("activation did not use current immutable version")
	}
	pair, err := tls.X509KeyPair(identity.CertificatePEM, identity.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("unchanged lego through fixed client directory; worker sealed key, edge decrypted current version; clientAuth-only PASS")
	// Real compiler emits the upstream mTLS certificate, independent member SNI,
	// original HTTP Host and full-chain CRLs into an immutable local artifact.
	issuer, err := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if err != nil {
		t.Fatal(err)
	}
	assertClientIdentityStatus(t, ctx, ca, certificate, issuer, ocsp.Good)
	crl, err := pkicrypto.NewStatusSigner(issuer).SignCRL(issuer.Metadata().ID, 1, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rootCRL, err := os.ReadFile(filepath.Join(online, "root.crl.der"))
	if err != nil {
		t.Fatal(err)
	}
	crls := append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rootCRL})...)
	// The gateway entry certificate is unrelated to the business ACME identity.
	entryCert, entryKey := fixtureEntry(t)
	state := edge.RuntimeState{Generation: "p6", Now: time.Now(), Materials: map[string]edge.Material{"entry": {Revision: 1, CertificatePEM: entryCert, KeyPEM: entryKey}, "client": {Revision: 1, CertificatePEM: identity.CertificatePEM, KeyPEM: identity.KeyPEM}, "root": {Revision: 1, TrustPEM: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw}), rootPEM...), CRLPEM: crls}}}
	snapshot := deploy.Snapshot{Version: "p6", Sites: []deploy.Site{{ID: "site", Revision: 1, Config: deploy.SiteConfig{Enabled: true, Domains: []string{"shop.example.test"}, DefaultTarget: deploy.TargetRef{ID: "a"}, EntryCertificate: &deploy.MaterialRef{ID: "entry", Revision: 1}, Routes: []deploy.Route{{Match: "prefix", Path: "/b/", StripPrefix: true, Target: deploy.TargetRef{ID: "b"}}}}}}}
	for _, name := range []string{"a", "b"} {
		ip := command(t, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containers[name])
		snapshot.Targets = append(snapshot.Targets, deploy.Target{ID: name, Revision: 1, Config: deploy.TargetConfig{Protocol: "https", TLSNameMode: "member", TLSServerNameMode: "verify_only", Trust: &deploy.MaterialRef{ID: "root", Revision: 1}, ClientCertificate: &deploy.MaterialRef{ID: "client", Revision: 1}, AllowedNetworks: []string{ip + "/32"}, Members: []deploy.TargetMember{{Address: ip, Port: 443, Weight: 1, TLSName: name + ".internal.test"}}}})
	}
	state.Health = map[string]edge.Health{}
	for i := range snapshot.Targets {
		snapshot.Targets[i].Config.Health = deploy.HealthPolicy{Enabled: true, Path: "/health"}
		state.Health[snapshot.Targets[i].ID] = edge.Health{TargetRevision: 1, Unhealthy: map[string]bool{}}
	}
	artifact, err := (nginx.Compiler{}).Compile(snapshot, state)
	if err != nil {
		t.Fatal("gateway compiler", err)
	}
	gatewayRoot := filepath.Join(lab, "gateway")
	if err = os.Mkdir(gatewayRoot, 0700); err != nil {
		t.Fatal(err)
	}
	for path, b := range artifact.Files {
		full := filepath.Join(gatewayRoot, path)
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		write(t, full, b)
	}
	gateway := start("gateway", "gateway.internal.test", "-p", "127.0.0.1::8443", "-v", gatewayRoot+":/gateway:ro", "--entrypoint", "nginx", nginxImage, "-p", "/gateway/", "-c", "nginx.conf", "-g", "daemon off;")
	gatewayAddress := command(t, "port", gateway, "8443/tcp")
	command(t, "exec", gateway, "sh", "-c", "for i in $(seq 1 20); do wget -qO- http://127.0.0.1:9090/version && exit 0; sleep 0.1; done; exit 1")
	entryRoots := x509.NewCertPool()
	entryRoots.AppendCertsFromPEM(entryCert)
	for _, path := range []string{"/", "/b/"} {
		status, body, err := nativeRequest(gatewayAddress, "shop.example.test", "shop.example.test", path, entryRoots, nil)
		want := "shop.example.test||SUCCESS"
		if path == "/b/" {
			want = "shop.example.test||SUCCESS"
		}
		if err != nil || status != 200 || body != want {
			t.Fatalf("real gateway/business mTLS %s status=%d body=%q err=%v", path, status, body, err)
		}
	}
	routeVerifier := edge.RouteVerifier{Probe: publishedFixtureProbe{Address: netip.MustParseAddrPort(gatewayAddress)}, Evidence: deployrepo.NewRuntime(db, nil, nil)}
	routePlan := edge.Plan{Snapshot: snapshot, Runtime: state}
	report, err := routeVerifier.Verify(ctx, routePlan, artifact.ID)
	if err != nil || !report.BusinessVerified || len(report.Routes) != 2 {
		t.Fatalf("real post-apply route closure %+v %v", report, err)
	}
	t.Run("TestABChallengeRoutingOnStandardPort80", func(t *testing.T) {
		leaves := map[string]string{}
		for _, name := range []string{"a", "b"} {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addresses[name], &tls.Config{RootCAs: roots, ServerName: name + ".internal.test", MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			peer := conn.ConnectionState().PeerCertificates[0]
			conn.Close()
			if peer.VerifyHostname(name+".internal.test") != nil {
				t.Fatal("A/B challenge routed to wrong native identity")
			}
			leaves[name] = peer.SerialNumber.String()
		}
		if leaves["a"] == leaves["b"] {
			t.Fatal("A/B shared issuance state")
		}
		t.Log("both independent native ACME states issued through own DNS name and actual port 80 before mTLS activation PASS")
	})
	t.Run("TestWrongSNIAndHTTPHostCannotDisableMTLS", func(t *testing.T) {
		for _, name := range []string{"a", "b"} {
			status, _, err := nativeRequest(addresses[name], name+".internal.test", "shop.example.test", "/", roots, nil, true)
			if err != nil || status != 400 {
				t.Fatal("native default mTLS listener did not reject missing client with valid Host and omitted SNI", status, err)
			}
			for _, probe := range []struct {
				sni, host string
				cert      *tls.Certificate
			}{{name + ".internal.test", "shop.example.test", nil}, {name + ".internal.test", "wrong.example.test", nil}, {"wrong.example.test", "shop.example.test", &pair}} {
				status, _, err := nativeRequest(addresses[name], probe.sni, probe.host, "/", roots, probe.cert)
				if err == nil && status == 200 {
					t.Fatal("cross virtual host bypass admitted")
				}
			}
		}
	})
	wrongSnapshot := snapshot
	wrongSnapshot.Version = "p6-wrong-name"
	wrongSnapshot.Targets = append([]deploy.Target(nil), snapshot.Targets...)
	wrongSnapshot.Targets[0].Config.Members = append([]deploy.TargetMember(nil), snapshot.Targets[0].Config.Members...)
	wrongSnapshot.Targets[0].Config.Members[0].TLSName = "wrong.internal.test"
	wrongArtifact, err := (nginx.Compiler{}).Compile(wrongSnapshot, state)
	if err != nil {
		t.Fatal(err)
	}
	wrongRoot := filepath.Join(lab, "wrong-gateway")
	for path, b := range wrongArtifact.Files {
		full := filepath.Join(wrongRoot, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		write(t, full, b)
	}
	wrongGateway := start("wrong-gateway", "wrong-gateway.internal.test", "-p", "127.0.0.1::8443", "-v", wrongRoot+":/gateway:ro", "--entrypoint", "nginx", nginxImage, "-p", "/gateway/", "-c", "nginx.conf", "-g", "daemon off;")
	wrongAddress := command(t, "port", wrongGateway, "8443/tcp")
	command(t, "exec", wrongGateway, "sh", "-c", "for i in $(seq 1 20); do wget -qO- http://127.0.0.1:9090/version && exit 0; sleep 0.1; done; exit 1")
	status, _, err := nativeRequest(wrongAddress, "shop.example.test", "shop.example.test", "/", entryRoots, nil)
	if err != nil || status != 502 {
		t.Fatal("actual Nginx failed to reject wrong explicit upstream TLSName", status, err)
	}
	// The actual health adapter follows the same verify-only contract and must
	// still reject a wrong verification name, even with a valid client key.
	healthProbe := health.Probe{Address: netip.MustParseAddrPort(addresses["a"]), Protocol: "https", HTTPHost: "shop.example.test", TLSName: "a.internal.test", TLSServerNameMode: "verify_only", Path: "/", Trust: &edge.Material{TrustPEM: rootPEM}, ClientCertificate: &edge.Material{CertificatePEM: identity.CertificatePEM, KeyPEM: identity.KeyPEM}}
	if err := (probe.HTTP{}).Check(ctx, healthProbe); err != nil {
		t.Fatal("verify-only health positive", err, "test coordinator context", ctx.Err())
	}
	healthProbe.HTTPHost = "wrong.example.test"
	if err := (probe.HTTP{}).Check(ctx, healthProbe); err == nil {
		t.Fatal("verify-only unknown Host bypass admitted")
	}
	healthProbe.HTTPHost = "shop.example.test"
	healthProbe.Trust = &edge.Material{TrustPEM: entryCert}
	if err := (probe.HTTP{}).Check(ctx, healthProbe); err == nil {
		t.Fatal("verify-only untrusted server chain admitted")
	}
	healthProbe.Trust = &edge.Material{TrustPEM: rootPEM}
	healthProbe.TLSName = "wrong.internal.test"
	if err := (probe.HTTP{}).Check(ctx, healthProbe); err == nil {
		t.Fatal("verify-only disabled hostname verification")
	}
	// The ordinary send-SNI mode remains safe but Nginx intentionally rejects
	// the original different HTTP Host with 421 under client verification.
	status, _, err = nativeRequest(addresses["a"], "a.internal.test", "shop.example.test", "/", roots, &pair)
	if err != nil || status != 421 {
		t.Fatalf("native SNI/Host limitation not preserved: %d %v", status, err)
	}
	assertRevokedRestore := nativeRestoreMaterialFence(t, db, edgeService, certapp.MaterialRef{ID: spec.ID, Kind: "certificate", Revision: spec.Revision, Purpose: "clientAuth"}, routePlan, gatewayRoot, gateway)
	// Commit authoritative revocation of the ACTUAL ACME order certificate.
	// Leave the business and gateway CRL bytes unchanged and do not reload:
	// a subsequent denied connection must therefore be native OCSP, not CRL.
	previousConnections := map[string]int{}
	for _, name := range []string{"a", "b"} {
		previousConnections[name] = latestBusinessConnection(t, containers[name], 0)
	}
	admin := statusapp.NewManagement(security{tx}, pkirepo.New(), audit.New(), pkicrypto.Random{}, nil)
	if err := admin.Revoke(ctx, management.ActorRef{UserID: "test-admin"}, string(issuer.Metadata().ID), fmt.Sprintf("%040x", certificate.SerialNumber), 1); err != nil {
		t.Fatal(err)
	}
	assertClientIdentityStatus(t, ctx, ca, certificate, issuer, ocsp.Revoked)
	assertRevokedRestore()
	if err := tx.Within(ctx, func(sc transaction.Scope) error {
		return edgeService.ValidateMaterialsWithin(sc, []certapp.MaterialRef{{ID: spec.ID, Kind: "certificate", Revision: spec.Revision, Purpose: "clientAuth"}})
	}); err == nil {
		t.Fatal("revoked managed client identity passed current publication material fence")
	}
	for _, path := range []string{"/", "/b/"} {
		status, _, err := nativeRequest(gatewayAddress, "shop.example.test", "shop.example.test", path, entryRoots, nil)
		if err != nil || status != 400 {
			t.Fatalf("native OCSP did not reject revoked actual ACME identity on fresh gateway/business connection path=%s status=%d err=%v", path, status, err)
		}
		name := "a"
		if path == "/b/" {
			name = "b"
		}
		connection := latestBusinessConnection(t, containers[name], 400)
		if connection <= previousConnections[name] {
			t.Fatalf("revoked request did not establish a fresh backend TLS connection: backend=%s before=%d rejected=%d", name, previousConnections[name], connection)
		}
		t.Logf("backend %s: prior connection %d, revoked fresh connection %d; TLS sessions disabled", name, previousConnections[name], connection)
	}
	t.Log("actual ACME client AIA + registered full-chain delegated OCSP: business ssl_ocsp on Good then authoritative Revoked rejection without CRL update/reload PASS")
	statusService := statusapp.New(tx, pkirepo.New(), pkicrypto.NewStatusSigner(issuer), nil)
	revokedCRL, err := statusService.CRL(ctx, issuer.Metadata().ID)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(lab, "business.crl"), append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revokedCRL}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rootCRL})...))
	for _, name := range []string{"a", "b"} {
		command(t, "exec", containers[name], "nginx", "-s", "reload", "-c", "/lab/"+name+".conf")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, _, err := nativeRequest(gatewayAddress, "shop.example.test", "shop.example.test", "/", entryRoots, nil)
		if err == nil && status != 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked gateway identity still admitted", status, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	report, err = routeVerifier.Verify(ctx, routePlan, artifact.ID)
	if err == nil || report.BusinessVerified {
		t.Fatal("actual revoked route failure reported healthy")
	}
	t.Log("OCSP-revoked identity remains rejected after authoritative full-chain CRL refresh PASS")
	t.Log("self CA + original business Nginx + actual compiled gateway Nginx mutual authentication; explicit TLS verification name, omitted wire SNI, original business Host PASS")
}

type sealFixture struct{ certapp.SecretSealer }

func (sealFixture) Open(string, []byte) ([]byte, error) {
	return nil, fmt.Errorf("worker has no leaf decryption capability")
}
func nativeRequest(address, sni, host, path string, roots *x509.CertPool, cert *tls.Certificate, noSNI ...bool) (int, string, error) {
	cfg := &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if len(noSNI) > 0 && noSNI[0] {
		cfg.ServerName = ""
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing server chain")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: sni, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}
	}
	tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", "https://"+address+path, nil)
	req.Host = host
	response, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	return response.StatusCode, string(b), err
}
func fixtureEntry(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"shop.example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func nativeCRL(t *testing.T, online string, revoked []pkidomain.Revocation) []byte {
	t.Helper()
	issuer, err := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkicrypto.NewStatusSigner(issuer).SignCRL(issuer.Metadata().ID, int64(len(revoked)+1), revoked, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(online, "root.crl.der"))
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: root})...)
}

type publishedFixtureProbe struct{ Address netip.AddrPort }

func (p publishedFixtureProbe) CheckRoute(ctx context.Context, r edge.RouteProbe) error {
	r.Address = p.Address
	return (probe.HTTP{}).CheckRoute(ctx, r)
}

// Reuse P4's production assembly, not a fake status responder. Only P6 opts
// into this test-process branch; P3's 45-second renewal signer stays unchanged.
func serveClientIdentityCA(init context.Context, db *pgxpool.Pool, issuer pkicrypto.Issuer, network string, denied []string) error {
	cfg := pki.Config{ServerNames: []string{"a.internal.test", "b.internal.test", "lego.internal.test"}, ClientNames: []string{"lego.internal.test"}, Origin: "https://ca.internal.test:8443", StatusOrigin: "http://ca.internal.test:8080", IdentityFile: "/lab/online/identity.agekey", RootCRLFile: "/lab/online/root.crl.der", RootOCSPCertificateFile: "/lab/online/root-ocsp.pem", RootOCSPSignerFile: "/lab/online/root-ocsp.age", ValidationNetworks: []string{network}, ValidationDenyNetworks: denied}
	service, err := pki.NewServer(cfg, db, issuer)
	if err != nil {
		return err
	}
	if err = pki.RegisterIssuer(init, db, issuer); err != nil {
		return err
	}
	if err = service.RegisterStatus(init, db); err != nil {
		return err
	}
	protocol := &http.Server{Addr: ":8443", Handler: service, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, TLSConfig: pki.BootstrapTLSConfig()}
	status := &http.Server{Addr: ":8080", Handler: service.StatusHandler(), ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 3 * time.Second}
	defer protocol.Close()
	defer status.Close()
	// This is the lifetime of the fixture CA across the entire mTLS scenario,
	// not a certificate, request, renewal or revocation deadline.
	runLimit := 90 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		runLimit *= 12
	}
	run, cancel := context.WithTimeout(context.Background(), runLimit)
	defer cancel()
	failures := make(chan error, 2)
	go func() { failures <- status.ListenAndServe() }()
	go func() { failures <- protocol.ListenAndServeTLS("/lab/transport.pem", "/lab/transport-key.pem") }()
	select {
	case err := <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-run.Done():
		return run.Err()
	}
}
func assertClientIdentityStatus(t *testing.T, ctx context.Context, container string, leaf *x509.Certificate, issuer pkicrypto.Issuer, want int) {
	t.Helper()
	address := command(t, "port", container, "8080/tcp")
	for _, check := range []struct {
		leaf, issuer *x509.Certificate
		want         int
	}{{leaf, issuer.Certificate, want}, {issuer.Certificate, issuer.Chain[0], ocsp.Good}} {
		if len(check.leaf.OCSPServer) != 1 || check.leaf.OCSPServer[0] != "http://ca.internal.test:8080/ocsp" {
			t.Fatal("missing full-chain standard OCSP AIA")
		}
		request, err := ocsp.CreateRequest(check.leaf, check.issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/ocsp", bytes.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		response, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		if err != nil || response.StatusCode != 200 {
			t.Fatal("standard OCSP response", response.StatusCode, err)
		}
		parsed, err := ocsp.ParseResponseForCert(body, check.leaf, check.issuer)
		if err != nil || parsed.Status != check.want || parsed.Certificate == nil || parsed.Certificate.CheckSignatureFrom(check.issuer) != nil {
			t.Fatal("signed full-chain status/delegation", err)
		}
	}
}

func latestBusinessConnection(t *testing.T, container string, status int) int {
	t.Helper()
	latest := 0
	for _, line := range strings.Split(command(t, "logs", "--tail", "100", container), "\n") {
		var connection, code int
		if n, err := fmt.Sscanf(line, "p6-connection=%d status=%d", &connection, &code); err == nil && n == 2 && (status == 0 || code == status) && connection > latest {
			latest = connection
		}
	}
	if latest == 0 {
		t.Fatal("missing native backend connection evidence", container, status)
	}
	return latest
}
