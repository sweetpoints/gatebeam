//go:build integration

package acme_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"gatebeam/internal/integration/certificateaccess"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/publication"
	"gatebeam/internal/modules/certificates"
	certapp "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/deployment/application/release"
	deploymentdomain "gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	"gatebeam/internal/modules/deployment/infrastructure/operations"
	identitymodule "gatebeam/internal/modules/identity"
	identityapp "gatebeam/internal/modules/identity/application"
	identityauth "gatebeam/internal/modules/identity/application/auth"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	identityotp "gatebeam/internal/modules/identity/infrastructure/otp"
	"gatebeam/internal/modules/identity/infrastructure/password"
	identitypg "gatebeam/internal/modules/identity/infrastructure/postgres"
	"gatebeam/internal/modules/ingress"
	ingressapp "gatebeam/internal/modules/ingress/application"
	ingressdomain "gatebeam/internal/modules/ingress/domain"
	ingresspg "gatebeam/internal/modules/ingress/infrastructure/postgres"
	pkistatus "gatebeam/internal/modules/pki/application/status"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	runtimefixture "gatebeam/tests/fixtures/deployment"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type publicEdge struct {
	db                       *pgxpool.Pool
	state, specID, releaseID string
	tx                       transaction.Runner
	revokePublisher          func()
	t                        *testing.T
	address                  string
	roots                    *x509.CertPool
	sites                    *ingressapp.Service
	draftID                  string
	draftRevision            int64
	name                     string
	actor                    ingressapp.ActorRef
	publisher                publication.ActorRef
	coordinator              *publication.Coordinator
	siteID                   string
	wantStatus               int
	edgeRole                 string
	receiptStage             string
	receiptVersion           string
	receiptDeadlineExpired   bool
	receiptNativeBudget      time.Duration
	receiptNativeElapsed     time.Duration
}

func nativeCommand(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("owned native fixture command %s: %v\n%s", args[0], e, out)
	}
	return strings.TrimSpace(string(out))
}
func startPublicEdge(t *testing.T, f *fixture, issuer pkicrypto.Issuer, specID, identityFile, providerRecipient string, beforePublish ...func(root, network, dsn, api, challengeURL string)) *publicEdge {
	t.Helper()
	binary := os.Getenv("GATEBEAM_I4_BINARY")
	dbContainer := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if binary == "" || dbContainer == "" {
		t.Fatal("fresh native gatebeam binary and owned PostgreSQL required")
	}
	root := t.TempDir()
	_ = os.Chmod(root, 0755)
	edgeFiles := filepath.Join(root, "edge")
	if err := os.Mkdir(edgeFiles, 0755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if e := os.Mkdir(state, 0777); e != nil {
		t.Fatal(e)
	}
	_ = os.Chmod(state, 0777)
	name := fmt.Sprintf("gatebeam-p5-%d", time.Now().UnixNano())
	network := name + "-net"
	nativeCommand(t, "network", "create", "--internal", network)
	observedEdge := &publicEdge{t: t, db: f.db, state: state, name: name}
	var stop sync.Once
	var ownedLogins []string
	quiesce := func() {
		stop.Do(func() {
			// Observe a failed publication before tearing down its authority.
			// Revoking role grants first can manufacture a restore_failed journal.
			if t.Failed() {
				observedEdge.diagnose()
				c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				out, _ := exec.CommandContext(c, "docker", "logs", name).CombinedOutput()
				cancel()
				t.Log(string(out))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = exec.CommandContext(ctx, "docker", "rm", "-f", name, name+"-api").Run()
			cancel()
			if err := runtimefixture.QuiesceRuntimeRoles(f.db, ownedLogins); err != nil {
				t.Error("owned native fixture database sessions did not quiesce", err)
			}
		})
	}
	t.Cleanup(func() {
		quiesce()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "network", "disconnect", network, dbContainer).Run()
		_ = exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	})
	subnet := nativeCommand(t, "network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", network)
	prefix, e := netip.ParsePrefix(subnet)
	if e != nil {
		t.Fatal(e)
	}
	// Fixed endpoints require an explicitly configured subnet on Docker26.
	// Re-reserve the pool selected by Docker before attaching fixture containers.
	nativeCommand(t, "network", "rm", network)
	nativeCommand(t, "network", "create", "--internal", "--subnet", prefix.String(), network)
	dbIP := prefix.Addr().Next().Next()
	edgeIP := dbIP.Next()
	apiIP := edgeIP.Next()
	nativeCommand(t, "network", "connect", "--ip", dbIP.String(), network, dbContainer)
	dsn, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	dsn.Host = net.JoinHostPort(dbIP.String(), "5432")
	q := dsn.Query()
	q.Set("search_path", f.db.Config().ConnConfig.RuntimeParams["search_path"])
	dsn.RawQuery = q.Encode()
	roles := runtimefixture.RuntimeRoles(t, f.db, quiesce)
	for _, login := range roles {
		ownedLogins = append(ownedLogins, login.Name)
	}
	apiDSN := *dsn
	apiDSN.User = url.UserPassword(roles["api"].Name, roles["api"].Password)
	workerDSN := *dsn
	workerDSN.User = url.UserPassword(roles["worker"].Name, roles["worker"].Password)
	dsn.User = url.UserPassword(roles["edge"].Name, roles["edge"].Password)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(800), Subject: pkix.Name{CommonName: "management.test"}, DNSNames: []string{"management.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, e := x509.CreateCertificate(rand.Reader, template, issuer.Certificate, &key.PublicKey, issuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...)
	for _, ca := range issuer.Chain {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Chain[len(issuer.Chain)-1].Raw})
	identity, e := os.ReadFile(identityFile)
	if e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{"management.pem": chain, "management.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), "roots.pem": roots, "materials.agekey": identity, "database": []byte(dsn.String())} {
		if e = os.WriteFile(filepath.Join(edgeFiles, name), data, 0444); e != nil {
			t.Fatal(e)
		}
	}
	cfg := bootstrap.Config{Environment: "production", Mode: "edge", DatabaseFile: "/fixture/database", CertificateIdentityFile: "/fixture/materials.agekey", CertificateProviderRecipient: providerRecipient, EdgeRoot: "/state", ManagementDomain: "management.test", ManagementAPIAddress: net.JoinHostPort(apiIP.String(), "8080"), ManagementCertificateFile: "/fixture/management.pem", ManagementKeyFile: "/fixture/management.key", ManagementTrustFile: "/fixture/roots.pem", ProtectedNetworks: []string{subnet}}
	if len(beforePublish) > 0 {
		cfg.ACMEWebRoot = "/challenges"
	}
	{
		if err := os.Mkdir(filepath.Join(root, "challenges"), 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "challenges"), 0777); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(cfg)
	if e = os.WriteFile(filepath.Join(edgeFiles, "edge.json"), body, 0444); e != nil {
		t.Fatal(e)
	}
	authFile := filepath.Join(t.TempDir(), "auth.agekey")
	if e = secrets.EnsureIdentity(authFile); e != nil {
		t.Fatal(e)
	}
	authSecrets, e := secrets.New(authFile)
	if e != nil {
		t.Fatal(e)
	}
	tx := postgres.NewRunner(f.db)
	clock := time.Now().UTC().Truncate(30 * time.Second).Add(-30 * time.Second)
	catalog := &ingressaccess.Catalog{}
	access := identitymodule.NewAccess(f.db, catalog)
	auth := identityauth.New(tx, identitypg.New(), audit.New(), password.New(), identityotp.New(), authSecrets, func() time.Time { return clock }, credential.New())
	auth.SetAccess(access)
	enrollment, e := auth.Bootstrap(context.Background(), "publisher")
	if e != nil {
		t.Fatal(e)
	}
	provisioning, _ := url.Parse(enrollment.ProvisioningURI)
	seed := provisioning.Query().Get("secret")
	code, _ := totp.GenerateCode(seed, clock)
	if _, e = auth.EnrollTOTP(context.Background(), enrollment.InviteID, "owned long publisher password", code); e != nil {
		t.Fatal(e)
	}
	clock = clock.Add(30 * time.Second)
	challenge, e := auth.BeginLogin(context.Background(), "publisher", "owned long publisher password")
	if e != nil {
		t.Fatal(e)
	}
	code, _ = totp.GenerateCode(seed, clock)
	session, e := auth.FinishLogin(context.Background(), challenge.ChallengeID, code)
	if e != nil {
		t.Fatal(e)
	}
	publisher, e := auth.Authenticate(context.Background(), session.Token)
	if e != nil {
		t.Fatal(e)
	}
	sites := ingress.New(f.db, ingressaccess.Authorizer{Identity: access})
	catalog.Ingress = sites
	materialSecrets, e := secrets.New(identityFile)
	if e != nil {
		t.Fatal(e)
	}
	security := &certificateaccess.Security{Authentication: auth, Access: access, Ingress: sites, Actor: publisher, Code: "invalid"}
	providerSealer, e := secrets.NewRecipient(providerRecipient)
	if e != nil {
		t.Fatal(e)
	}
	resourceManager := certapp.NewManagement(security, certificateaccess.Graph{Ingress: sites}, certpg.New(), certcrypto.Crypto{}, materialSecrets, providerSealer, audit.New())
	certificateActor := certapp.ActorRef{UserID: publisher.UserID, AuthVersion: publisher.AuthVersion, CredentialKind: string(publisher.CredentialKind), CredentialID: publisher.CredentialID}
	dnsCredential := certapp.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "host.example"}
	if _, e = resourceManager.SaveCredential(context.Background(), certificateActor, "", 0, dnsCredential, []byte("owned-fixture-token")); e == nil {
		t.Fatal("credential write without fresh MFA")
	}
	clock = clock.Add(30 * time.Second)
	security.Code, _ = totp.GenerateCode(seed, clock)
	if _, e = resourceManager.SaveCredential(context.Background(), certificateActor, "", 0, dnsCredential, []byte("owned-fixture-token")); e != nil {
		t.Fatal("fresh MFA credential management", e)
	}
	if _, e = resourceManager.SaveCredential(context.Background(), certificateActor, "", 0, dnsCredential, []byte("owned-fixture-token")); e == nil {
		t.Fatal("MFA proof replay accepted")
	}
	actor := ingressapp.ActorRef{UserID: publisher.UserID, AuthVersion: publisher.AuthVersion, CredentialKind: string(publisher.CredentialKind), CredentialID: publisher.CredentialID}
	config := ingressdomain.SiteConfig{Enabled: true, Domains: []string{"host.example"}, EntryCertificate: &ingressdomain.MaterialRef{ID: specID, Revision: 1, Status: "unavailable"}, Maintenance: ingressdomain.MaintenancePolicy{Enabled: true, Status: 503, Message: "published"}}
	site, e := sites.CreateSite(context.Background(), actor, ingressapp.CreateSite{Name: "published", Config: config})
	if e != nil {
		t.Fatal(e)
	}
	draft, e := sites.CreateSite(context.Background(), actor, ingressapp.CreateSite{Name: "unrelated", Config: ingressdomain.SiteConfig{Enabled: true, Domains: []string{"unrelated.example"}, Maintenance: ingressdomain.MaintenancePolicy{Enabled: true, Status: 503, Message: "unpublished"}}})
	if e != nil {
		t.Fatal(e)
	}
	reader := certificates.NewReader(f.db)
	reader.SetLeafStatus(certificatematerials.LeafStatus{Owner: pkistatus.NewMaterials(pkipg.New())})
	coordinator := publication.New(tx, access, sites, certificatematerials.Adapter{Owner: reader}, deployment.New(), jobs.New(f.db), audit.New(), identifiers.Generator{})
	actorRef := publication.ActorRef{UserID: publisher.UserID, AuthVersion: publisher.AuthVersion, CredentialKind: string(publisher.CredentialKind), CredentialID: publisher.CredentialID}
	apiFiles := filepath.Join(root, "api")
	if len(beforePublish) > 0 {
		if err := os.Mkdir(apiFiles, 0755); err != nil {
			t.Fatal(err)
		}
		keyBytes, err := os.ReadFile(authFile)
		if err != nil {
			t.Fatal(err)
		}
		apiCfg := bootstrap.Config{Environment: "production", Mode: "api", DatabaseFile: "/api/database", IdentityFile: "/api/identity.agekey", APIListen: net.JoinHostPort(apiIP.String(), "8080"), APIPrivateNetwork: subnet, APIOrigin: "https://management.test", ManagementDomain: "management.test", ManagementAddress: net.JoinHostPort(edgeIP.String(), "8443"), ManagementCertificateFile: "/api/management.pem", ManagementTrustFile: "/api/roots.pem"}
		body, err := json.Marshal(apiCfg)
		if err != nil {
			t.Fatal(err)
		}
		for file, data := range map[string][]byte{"api.json": body, "database": []byte(apiDSN.String()), "identity.agekey": keyBytes, "management.pem": chain, "roots.pem": roots} {
			if err := os.WriteFile(filepath.Join(apiFiles, file), data, 0444); err != nil {
				t.Fatal(err)
			}
		}
	}
	address := ""
	startNative := func() {

		nativeCommand(t, "create", "--name", name, "--network", "bridge", "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=64m,mode=1777", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-p", "127.0.0.1::8443", "-p", "127.0.0.1::8080", "-v", edgeFiles+":/fixture:ro", "-v", state+":/state", "-v", filepath.Join(root, "challenges")+":/challenges:ro", "-v", binary+":/gatebeam:ro", "--entrypoint", "/gatebeam", "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "--config", "/fixture/edge.json")
		nativeCommand(t, "network", "connect", "--ip", edgeIP.String(), network, name)
		nativeCommand(t, "start", name)
		address = nativeCommand(t, "port", name, "8443/tcp")
		// Begin business-certificate assertions after the initial process has
		// exposed its bootstrap management TLS listener. Its startup observer
		// is separate from the publication and renewal observation windows.
		{
			started := time.Now()
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(roots)
			preparation := 5 * time.Second
			if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
				preparation *= 12
			}
			until := started.Add(preparation)
			for {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: pool, ServerName: "management.test", MinVersion: tls.VersionTLS12})
				if err == nil {
					conn.Close()
					t.Logf("initial management TLS ready: elapsed=%s preparation_budget=%s; renewal certificate deadline remains 10s", time.Since(started), preparation)
					break
				}
				if time.Now().After(until) {
					t.Fatal("bootstrap management TLS readiness", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		if len(beforePublish) > 0 {
			nativeCommand(t, "run", "-d", "--name", name+"-api", "--network", network, "--ip", apiIP.String(), "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "256m", "--cpus", ".5", "--pids-limit", "64", "--tmpfs", "/tmp:size=16m,mode=1777", "--mount", "type=bind,src="+apiFiles+",dst=/api,readonly", "--mount", "type=bind,src="+binary+",dst=/gatebeam,readonly", "--entrypoint", "/gatebeam", "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "--config", "/api/api.json")
		}
	}
	if len(beforePublish) > 0 {
		startNative()
		beforePublish[0](root, network, workerDSN.String(), cfg.ManagementAPIAddress, "http://"+nativeCommand(t, "port", name, "8080/tcp"))
	}
	candidate, e := coordinator.Prepare(context.Background(), actorRef, []string{site.ID}, map[string]int64{"site:" + site.ID: 1})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = coordinator.Publish(context.Background(), actorRef, candidate.ID); e != nil {
		t.Fatal(e)
	}
	revoke := func() {
		if e := auth.Logout(context.Background(), session.Token, session.CSRFToken); e != nil {
			t.Fatal(e)
		}
		if e := access.Require(context.Background(), publisher, identityapp.Publish, []string{site.ID}); e == nil {
			t.Fatal("old publisher session still authorized")
		}
	}
	if len(beforePublish) == 0 {
		startNative()
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(roots)
	*observedEdge = publicEdge{db: f.db, state: state, edgeRole: roles["edge"].Name, actor: actor, publisher: actorRef, coordinator: coordinator, siteID: site.ID, wantStatus: 503, specID: specID, releaseID: candidate.ID, tx: tx, revokePublisher: revoke, t: t, address: address, roots: pool, sites: sites, draftID: draft.ID, draftRevision: draft.Revision, name: name}
	return observedEdge
}
func (e *publicEdge) wait(expected []byte) {
	e.t.Helper()
	e.waitWithin(expected, 10*time.Second, false)
}

func (e *publicEdge) waitInitial(expected []byte) {
	e.t.Helper()
	e.waitWithin(expected, operations.OperationObservationTimeout, true)
}

func (e *publicEdge) waitWithin(expected []byte, budget time.Duration, initial bool) {
	e.t.Helper()
	started := time.Now()
	deadline := started.Add(budget)
	ctx, cancel := context.WithDeadline(e.t.Context(), deadline)
	defer cancel()
	e.receiptStage, e.receiptVersion = "certificate", ""
	e.receiptDeadlineExpired = false
	e.receiptNativeBudget, e.receiptNativeElapsed = 0, 0
	attempts, verified := 0, 0
	peerMatches := false
	nextStatus := started
	for {
		if initial && !time.Now().Before(nextStatus) {
			nextStatus = time.Now().Add(time.Second)
			statusContext, done := context.WithTimeout(ctx, 3*time.Second)
			var state string
			err := e.db.QueryRow(statusContext, "SELECT state FROM deployment_releases WHERE id=$1", e.releaseID).Scan(&state)
			done()
			if err == nil && (state == "failed" || state == "restored" || state == "restore_failed") {
				e.t.Fatalf("initial publication entered terminal failure: state=%s", state)
			}
		}
		attempts++
		peerMatches = false
		probe, stopProbe := context.WithTimeout(ctx, time.Second)
		raw, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{RootCAs: e.roots, ServerName: "host.example", MinVersion: tls.VersionTLS12}}).DialContext(probe, "tcp", e.address)
		stopProbe()
		if err == nil {
			conn := raw.(*tls.Conn)
			verified++
			peer := conn.ConnectionState().PeerCertificates[0].Raw
			conn.Close()
			peerMatches = bytes.Equal(peer, expected)
			if peerMatches && e.receiptMatches(ctx, expected) && ctx.Err() == nil {
				e.t.Logf("native owner observed: elapsed=%s budget=%s attempts=%d verified_handshakes=%d receipt_stage=%s native_probe_elapsed=%s native_probe_budget=%s", time.Since(started), budget, attempts, verified, e.receiptStage, e.receiptNativeElapsed, e.receiptNativeBudget)
				break
			}
		}
		if ctx.Err() != nil {
			e.t.Logf("native owner observation: elapsed=%s budget=%s attempts=%d verified_handshakes=%d last_peer_matches=%t receipt_stage=%s receipt_deadline_expired=%t", time.Since(started), budget, attempts, verified, peerMatches, e.receiptStage, e.receiptDeadlineExpired)
			e.t.Fatal("native edge did not serve current owner certificate", err, nativeCommand(e.t, "logs", e.name))
		}
		time.Sleep(100 * time.Millisecond)
	}
	var draft ingressdomain.Site
	err := e.tx.Within(context.Background(), func(sc transaction.Scope) error {
		graph, err := ingresspg.New().Graph(sc)
		if err != nil {
			return err
		}
		for _, site := range graph.Sites {
			if site.ID == e.draftID {
				draft = site
			}
		}
		return nil
	})
	if err != nil || draft.Revision != e.draftRevision || draft.PublishedRevision != 0 || draft.Draft.Maintenance.Message != "unpublished" {
		e.t.Fatal("derived renewal published unrelated draft", err, draft)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots, ServerName: "host.example"}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, e.address)
	}}}
	response, err := client.Get("https://host.example/")
	if err != nil {
		e.t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != e.wantStatus {
		e.t.Fatal("published routing changed", response.StatusCode)
	}
}

// diagnose runs before fixture destruction and intentionally selects no payload,
// PEM, credentials, request bodies, SQL arguments or secret configuration.
func (e *publicEdge) diagnose() {
	// The original assertion has already failed. Observe only that same
	// in-flight first publication; never renew, republish, retry TLS, or turn
	// a late success into a passing original certificate assertion.
	if e.releaseID != "" {
		started := time.Now()
		observation, stop := context.WithTimeout(context.Background(), 45*time.Second)
		last, observations := "unreported", 0
	observe:
		for {
			step, done := context.WithTimeout(observation, 3*time.Second)
			var state string
			err := e.db.QueryRow(step, "SELECT state FROM deployment_releases WHERE id=$1", e.releaseID).Scan(&state)
			done()
			observations++
			if err != nil {
				break
			}
			switch state {
			case "queued", "preparing", "validated", "applying", "verifying", "restoring":
				last = state
			case "succeeded", "failed", "restored", "restore_failed":
				last = state
				break observe
			default:
				break observe
			}
			select {
			case <-observation.Done():
				break observe
			case <-time.After(time.Second):
			}
		}
		e.t.Logf("post-failure existing-publication observation before teardown: state=%s observations=%d elapsed=%s deadline_expired=%t; original certificate assertion remains failed", last, observations, time.Since(started), errors.Is(observation.Err(), context.DeadlineExceeded))
		stop()
	}
	e.t.Logf("last receipt check: stage=%s deadline_expired=%t expected_release=%s native_probe_elapsed=%s native_probe_budget=%s", e.receiptStage, e.receiptDeadlineExpired, e.releaseID, e.receiptNativeElapsed, e.receiptNativeBudget)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, q := range []string{
		"SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT kind,status,attempt,deadline FROM jobs ORDER BY created_at LIMIT 32) s",
		"SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT id,state,observed_version,restored_version FROM deployment_releases LIMIT 8) s",
		"SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT release_id,artifact_id,version,verified_at,material_bindings FROM deployment_runtime) s",
		"SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT release_id,stage,cause FROM deployment_execution_reports LIMIT 8) s",
	} {
		var safe []byte
		if err := e.db.QueryRow(ctx, q).Scan(&safe); err != nil {
			e.t.Log("diagnostic query unavailable")
		} else {
			e.t.Log("body-free metadata", string(safe))
		}
	}
	b, err := os.ReadFile(filepath.Join(e.state, "journal.json"))
	var journal deploymentdomain.ApplyJournal
	if err == nil && json.Unmarshal(b, &journal) == nil {
		e.t.Logf("local journal %+v host_utc=%s", journal, time.Now().UTC().Format(time.RFC3339Nano))
	}
}
func (e *publicEdge) receiptMatches(ctx context.Context, expected []byte) bool {
	started := time.Now()
	e.receiptStage, e.receiptVersion = "runtime", ""
	e.receiptNativeBudget, e.receiptNativeElapsed = 0, 0
	e.receiptDeadlineExpired = ctx.Err() != nil
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil {
		return false
	}
	budget := time.Until(deadline)
	// This fixture is called synchronously by its wait loops. Record only the
	// last proof stage, never SQL errors, certificate bytes or credentials.
	defer func() {
		e.receiptDeadlineExpired = ctx.Err() != nil
		if e.receiptDeadlineExpired {
			e.t.Logf("native owner receipt observation expired: elapsed=%s remaining_budget_at_start=%s stage=%s native_probe_elapsed=%s native_probe_budget=%s", time.Since(started), budget, e.receiptStage, e.receiptNativeElapsed, e.receiptNativeBudget)
		}
	}()
	var artifact, version, status, releaseID string
	var bindingsJSON, certPEM []byte
	err := e.db.QueryRow(ctx, `SELECT active.release_id::text,active.artifact_id,active.version,r.state,active.material_bindings,v.certificate_pem FROM deployment_runtime active JOIN deployment_releases r ON r.id=active.release_id JOIN certificates_attempts a ON a.spec_id=$1 JOIN certificates_versions v ON v.id=a.current_version WHERE active.id`, e.specID).Scan(&releaseID, &artifact, &version, &status, &bindingsJSON, &certPEM)
	if err != nil || status != "succeeded" || releaseID != e.releaseID {
		return false
	}
	e.receiptStage = "publication-apply"
	if !e.publicationApplyComplete(ctx) {
		return false
	}
	e.receiptStage = "local-journal"
	b, err := os.ReadFile(filepath.Join(e.state, "journal.json"))
	var journal deploymentdomain.ApplyJournal
	if err != nil || json.Unmarshal(b, &journal) != nil || journal.ReceiptPending || (journal.State != deploymentdomain.Succeeded && journal.State != deploymentdomain.Restored) || journal.ArtifactID != artifact || journal.Version != version {
		return false
	}
	e.receiptStage = "current-certificate"
	block, _ := pem.Decode(certPEM)
	if block == nil || !bytes.Equal(block.Bytes, expected) {
		return false
	}
	e.receiptStage = "material-bindings"
	var bindings []release.MaterialBinding
	if json.Unmarshal(bindingsJSON, &bindings) != nil {
		return false
	}
	found := false
	for _, binding := range bindings {
		if binding.ID == e.specID && binding.Digest == (certcrypto.Crypto{}).Digest(certPEM) {
			found = true
		}
	}
	if !found {
		return false
	}
	e.receiptStage = "native-version"
	probeStarted := time.Now()
	e.receiptNativeBudget = time.Until(deadline)
	matched := e.nativeVersionMatches(ctx, version)
	e.receiptNativeElapsed = time.Since(probeStarted)
	if matched {
		e.receiptStage = "complete"
		e.receiptVersion = version
	}
	return matched
}

func (e *publicEdge) nativeVersionMatches(ctx context.Context, version string) bool {
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return false
	}
	out, err := exec.CommandContext(ctx, "docker", "exec", e.name, "wget", "-qO-", "http://127.0.0.1:9090/version").Output()
	return err == nil && ctx.Err() == nil && strings.TrimSpace(string(out)) == version
}

// Keep receipt ownership separate from the continuously scheduled health/DNS queue.
func (e *publicEdge) publicationApplyComplete(ctx context.Context) bool {
	var status string
	err := e.db.QueryRow(ctx, `SELECT status FROM jobs WHERE kind='deployment.apply' AND key=$1`, e.releaseID).Scan(&status)
	return err == nil && status == "completed"
}

func TestPublicationReceiptRequiresItsCompletedApplyNotGlobalQueueIdle(t *testing.T) {
	db := testkit.Postgres(t)
	queue := jobs.New(db)
	edge := &publicEdge{db: db, releaseID: "owned-release"}
	id, err := queue.Enqueue(t.Context(), "deployment.apply", edge.releaseID, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "running", "failed", "completed"} {
		if _, err := db.Exec(t.Context(), "UPDATE jobs SET status=$1 WHERE id=$2", state, id); err != nil {
			t.Fatal(err)
		}
		if got, want := edge.publicationApplyComplete(t.Context()), state == "completed"; got != want {
			t.Errorf("owned apply state=%s: complete=%t want=%t", state, got, want)
		}
	}
	for _, work := range []struct{ kind, key string }{
		{"deployment.generation", "later-health-dns"},
		{"deployment.apply", "different-release"},
	} {
		if _, err := queue.Enqueue(t.Context(), work.kind, work.key, json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if !edge.publicationApplyComplete(t.Context()) {
		t.Error("unrelated queued work hid the completed owned apply")
	}
	edge.releaseID = "absent-release"
	if edge.publicationApplyComplete(t.Context()) {
		t.Error("missing owned apply accepted")
	}
}
