//go:build integration

// Package multinode owns isolated two-project fixtures, never existing gateways.
package multinode

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/operations"
	pkiapp "gatebeam/internal/modules/pki/application"
	pkidomain "gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	rolefixture "gatebeam/tests/fixtures/deployment"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.yaml.in/yaml/v3"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var Modes = map[string]string{"nginx": "edge", "management": "api", "background-jobs": "worker", "log-query": "query"}
var HealthPorts = map[string]int{"nginx": 19091, "management": 19092, "background-jobs": 19093, "log-query": 19095}

type Node struct {
	portsMu             sync.Mutex
	ports               map[string]string
	Info                domain.NodeDeployment
	ComposeFile, Router string
	Secrets             map[string]string
	Configs             map[string]bootstrap.Config
	APIClient           *http.Client `json:"-"`
	CAAddress           string
	CAClient            *http.Client `json:"-"`
	PublicClient        *http.Client `json:"-"`
}
type Lab struct {
	TestIssuer                          *pkicrypto.Issuer `json:"-"`
	BusinessInstance                    *Business
	CanarySiteID                        string
	Pool                                *pgxpool.Pool
	Nodes                               []*Node
	Trust                               []byte
	CAAddress, CAContainer, CADirectory string
	Network                             string
	Run                                 string
}

func Docker(t testing.TB, args ...string) string {
	t.Helper()
	return dockerCommand(t, 25*time.Second, args...)
}

// Only initial owned lab preparation receives the aggregate CI budget. Fault,
// upgrade and recovery commands keep Docker's original 25-second bound.
func prepareDocker(t testing.TB, args ...string) string {
	t.Helper()
	return dockerCommand(t, cleanupBudget(25*time.Second), args...)
}
func dockerCommand(t testing.TB, budget time.Duration, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	started := time.Now()
	out, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if e != nil {
		// Keep fault/upgrade command deadlines unchanged. Record only a fixed
		// network operation class, never arbitrary arguments or private config.
		if args[0] == "network" && len(args) > 1 && (args[1] == "connect" || args[1] == "disconnect") {
			t.Logf("owned network operation failed: operation=%s elapsed=%s budget=%s command_context=%v test_context=%v", args[1], time.Since(started), budget, ctx.Err(), t.Context().Err())
		}
		t.Fatalf("owned lab Docker %s failed: %v %s", args[0], e, out)
	}
	return strings.TrimSpace(string(out))
}

// Cleanup is outside the scenario's functional clocks. Each command owns a
// fresh finite context; earlier node shutdowns cannot cancel image removal.
func cleanupCommand(run func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupBudget(20*time.Second))
	defer cancel()
	return run(ctx)
}
func CleanupDocker(t testing.TB, args ...string) {
	t.Helper()
	if err := cleanupCommand(func(ctx context.Context) error { return exec.CommandContext(ctx, "docker", args...).Run() }); err != nil {
		t.Errorf("owned Docker cleanup %s failed: %v", args[0], err)
	}
}

func cleanupBudget(base time.Duration) time.Duration {
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		return 12 * base
	}
	return base
}
func (n *Node) Compose(t testing.TB, args ...string) string {
	t.Helper()
	return Docker(t, append([]string{"compose", "-p", n.Info.StoragePrefix, "-f", n.ComposeFile}, args...)...)
}
func (n *Node) prepareCompose(t testing.TB, args ...string) string {
	t.Helper()
	return prepareDocker(t, append([]string{"compose", "-p", n.Info.StoragePrefix, "-f", n.ComposeFile}, args...)...)
}
func (n *Node) Port(t testing.TB, port int) string {
	t.Helper()
	// Addresses are stable during individual role replacement. Network topology
	// changes must refresh this cache before the next readiness/recovery clock.
	n.portsMu.Lock()
	defer n.portsMu.Unlock()
	key := n.Router + "/" + strconv.Itoa(port)
	if address, ok := n.ports[key]; ok {
		return address
	}
	address := Docker(t, "port", n.Router, fmt.Sprint(port)+"/tcp")
	if n.ports == nil {
		n.ports = map[string]string{}
	}
	n.ports[key] = address
	return address
}

func (n *Node) RefreshPorts(t testing.TB) {
	t.Helper()
	n.portsMu.Lock()
	var ports []int
	for key := range n.ports {
		if raw, ok := strings.CutPrefix(key, n.Router+"/"); ok {
			if port, err := strconv.Atoi(raw); err == nil {
				ports = append(ports, port)
			}
		}
	}
	n.ports = nil
	n.portsMu.Unlock()
	sort.Ints(ports)
	for _, port := range ports {
		n.Port(t, port)
	}
}

func (n *Node) Health(t testing.TB, role string) lifecycle.Snapshot {
	t.Helper()
	state, err := n.ProbeHealth(t, role)
	if err != nil {
		t.Fatal("owned role health unavailable", role, err)
	}
	return state
}

// ProbeHealth lets an existing bounded restart loop distinguish transport
// startup from an actual not-ready role. A failed probe is never a snapshot.
func (n *Node) ProbeHealth(t testing.TB, role string) (lifecycle.Snapshot, error) {
	t.Helper()
	client := &http.Client{Timeout: operations.HealthRequestTimeout}
	r, err := client.Get("http://" + n.Port(t, HealthPorts[role]) + "/status")
	if err != nil {
		return lifecycle.Snapshot{}, err
	}
	defer r.Body.Close()
	var out lifecycle.Snapshot
	if r.StatusCode != 200 || json.NewDecoder(io.LimitReader(r.Body, 32769)).Decode(&out) != nil {
		return lifecycle.Snapshot{}, fmt.Errorf("invalid owned role health: status=%d", r.StatusCode)
	}
	return out, nil
}

func (l *Lab) LogManagementReadiness(t testing.TB) {
	t.Helper()
	for i, node := range l.Nodes {
		state, err := node.ProbeHealth(t, "management")
		t.Logf("management readiness after failed request: node=%d transport=%s ready=%t probe=%s",
			i, observationFailureClass(err), state.Ready[lifecycle.Management], probeClasses(state)[lifecycle.Management])
	}
}

func (n *Node) Wait(t testing.TB, role, cap string) {
	t.Helper()
	n.wait(t, role, cap, 10*time.Second)
}
func (n *Node) wait(t testing.TB, role, cap string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	address := n.Port(t, HealthPorts[role])
	lastStatus := 0
	var lastError error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(t.Context(), operations.HealthRequestTimeout)
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+address+"/readyz/"+cap, nil)
		r, e := http.DefaultClient.Do(req)
		cancel()
		lastError = e
		if e == nil {
			lastStatus = r.StatusCode
			r.Body.Close()
			if r.StatusCode == 200 {
				return
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	{
		health, healthError := n.ProbeHealth(t, role)
		t.Logf("owned readiness probe after deadline: transport_class=%s probe_classes=%v", observationFailureClass(healthError), probeClasses(health))
		metadata := func(args ...string) (string, bool) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "docker", args...).Output()
			return strings.TrimSpace(string(out)), err != nil
		}
		fresh, portUnavailable := metadata("port", n.Router, fmt.Sprint(HealthPorts[role])+"/tcp")
		state, stateUnavailable := metadata("inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", n.Router)
		roleState, roleUnavailable := metadata("ps", "-a", "--filter", "label=com.docker.compose.project="+n.Info.StoragePrefix, "--filter", "label=com.docker.compose.service="+role, "--format", "{{.State}} {{.Status}}")
		t.Logf("owned readiness endpoint: cached=%s current=%s metadata_unavailable=%t router=%s router_state_unavailable=%t role_state=%s role_state_unavailable=%t", address, fresh, portUnavailable, state, stateUnavailable, roleState, roleUnavailable)
	}
	t.Fatal("owned role readiness deadline", "role", role, "capability", cap, "last_status", lastStatus, "last_error", lastError, "logs", n.Compose(t, "logs", "--tail", "8", role))
}

// Initial administrative fixture creation is preparation, before any timed
// upgrade, fault or business probe. Keep the shared functional client intact.
func (n *Node) prepareRequest(t testing.TB, method, path string, body []byte, cookie, csrf string) (int, []byte) {
	t.Helper()
	client := *n.PublicClient
	client.Timeout = cleanupBudget(client.Timeout)
	return n.request(t, &client, method, path, body, cookie, csrf)
}
func (n *Node) Request(t testing.TB, method, path string, body []byte, cookie, csrf string) (int, []byte) {
	t.Helper()
	return n.request(t, n.PublicClient, method, path, body, cookie, csrf)
}
func (n *Node) request(t testing.TB, client *http.Client, method, path string, body []byte, cookie, csrf string) (int, []byte) {
	t.Helper()
	req, e := http.NewRequestWithContext(t.Context(), method, "https://management.dual.test"+path, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: cookie})
	}
	if method != "GET" && method != "HEAD" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://management.dual.test")
		req.Header.Set("X-CSRF-Token", csrf)
	}
	r, e := client.Do(req)
	if e != nil {
		t.Fatal("owned gateway request failed", e)
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		t.Fatal(e)
	}
	return r.StatusCode, raw
}
func (n *Node) Admin(t testing.TB, operation string) []byte {
	t.Helper()
	return n.admin(t, operation, 25*time.Second)
}
func (n *Node) admin(t testing.TB, operation string, budget time.Duration) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	args := []string{"compose", "-p", n.Info.StoragePrefix, "-f", n.ComposeFile, "run", "--no-deps", "--rm", "-T", "--entrypoint", "/usr/local/bin/gatebeam-admin", "nginx", "--operation", operation, "--config", "/run/gatebeam/edge.json"}
	raw, e := exec.CommandContext(ctx, "docker", args...).Output()
	if e != nil {
		t.Fatal("owned node admin failed", operation, e)
	}
	return raw
}
func (l *Lab) Activate(t testing.TB) {
	t.Helper()
	proof := []nodes.ActivationProbe{}
	for _, n := range l.Nodes {
		for role, caps := range map[string][]string{"nginx": {lifecycle.Data}, "management": {lifecycle.Management}, "background-jobs": {lifecycle.GlobalJobs, lifecycle.LocalCleanup}, "log-query": {lifecycle.Query}} {
			for _, cap := range caps {
				// Initial owned lab startup is preparation, not fault recovery.
				n.wait(t, role, cap, cleanupBudget(10*time.Second))
			}
		}
		state := n.Health(t, "nginx")
		p := nodes.ActivationProbe{Node: n.Info.Node, ArtifactID: state.Details["artifact_id"], Generation: state.Details["generation"], Images: map[string]string{}}
		for role, r := range n.Info.Roles {
			p.Images[role] = strings.Split(r.Image, "@")[1]
		}
		proof = append(proof, p)
	}
	if e := postgres.NewRunner(l.Pool).Within(t.Context(), func(sc transaction.Scope) error { return deployment.NewNodes().ActivateVerifiedWithin(sc, proof) }); e != nil {
		t.Fatal(e)
	}
}
func Start(t testing.TB) *Lab {
	t.Helper()
	validateInputs(t)
	probe := os.Getenv("GATEBEAM_COMPOSE_PROBE_BINARY")
	binary := os.Getenv("GATEBEAM_COMPOSE_GATEWAY_BINARY")
	admin := os.Getenv("GATEBEAM_COMPOSE_ADMIN_BINARY")
	dbContainer := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if probe == "" || binary == "" || admin == "" || !strings.HasPrefix(dbContainer, "gatebeam-f2-") {
		t.Fatal("fresh owned lab binaries and external check-db fixture required")
	}
	run := fmt.Sprintf("gatebeam-dual-%d", time.Now().UnixNano())
	network := run + "-vpc"
	prepareDocker(t, "network", "create", "--subnet", "10.254.248.0/24", "--label", "gatebeam.fixture.run="+run, network)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupBudget(15*time.Second))
		defer cancel()
		exec.CommandContext(ctx, "docker", "network", "disconnect", network, dbContainer).Run()
		if e := exec.CommandContext(ctx, "docker", "network", "rm", network).Run(); e != nil {
			t.Error("owned lab network cleanup failed", e)
		}
	})
	prepareDocker(t, "network", "connect", "--alias", "database", network, dbContainer)
	dbIP := prepareDocker(t, "inspect", "--format", "{{(index .NetworkSettings.Networks "+strconv.Quote(network)+").IPAddress}}", dbContainer)
	pool := testkit.Postgres(t)
	lab := &Lab{Pool: pool, Network: network, Run: run}
	var consumers []*Node
	var consumerLogins []string
	var consumersStopped sync.Once
	stopConsumers := func() {
		consumersStopped.Do(func() {
			for _, node := range consumers {
				// Both nodes share this fixture's schema. No role/grant teardown
				// may race a still-serving peer's database transactions.
				CleanupDocker(t, "compose", "-p", node.Info.StoragePrefix, "-f", node.ComposeFile, "stop", "--timeout", "2")
			}
			if err := rolefixture.QuiesceRuntimeRoles(pool, consumerLogins); err != nil {
				t.Error("owned runtime role sessions did not quiesce before grant teardown", err)
			}
		})
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_, file, _, _ := runtime.Caller(0)
	project := filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
	production, e := os.ReadFile(filepath.Join(project, "compose.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	offline := filepath.Join(root, "offline")
	online := filepath.Join(root, "online")
	if e = (pkicrypto.Bootstrapper{}).Generate(t.Context(), pkiapp.BootstrapCommand{RootDirectory: offline, OnlineDirectory: online, RootName: "dual fixture root", IntermediateName: "dual fixture issuer", StatusOrigin: "http://ca.dual.test:8081"}); e != nil {
		t.Fatal("CA bootstrap", e)
	}
	caConfig := pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")}
	issuer, e := pkicrypto.LoadIssuer(caConfig)
	if e != nil {
		t.Fatal("CA load", e)
	}
	lab.TestIssuer = &issuer
	trust, e := os.ReadFile(caConfig.RootFile)
	if e != nil {
		t.Fatal(e)
	}
	lab.Trust = trust
	pair := func(name string, usage pkidomain.Usage) ([]byte, []byte) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
		if e != nil {
			t.Fatal(e)
		}
		policy, e := pkidomain.NewPolicy([]string{name}, usage)
		if e != nil {
			t.Fatal(e)
		}
		der, e := issuer.SignCSR(csr, policy, []string{name}, big.NewInt(time.Now().UnixNano()), time.Now(), time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		private, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	mgmtCert, mgmtKey := pair("management.dual.test", pkidomain.ServerAuth)
	policies := secrets.RolePolicy{}
	keys := []map[string]string{{}, {}}
	own := []map[string]string{{}, {}}
	for i := 0; i < 2; i++ {
		for _, role := range []string{"api", "provider", "notification", "leaf"} {
			path := filepath.Join(root, fmt.Sprintf("%d-%s.agekey", i, role))
			if e = secrets.EnsureIdentity(path); e != nil {
				t.Fatal(e)
			}
			s, e := secrets.New(path)
			if e != nil {
				t.Fatal(e)
			}
			keys[i][role] = path
			own[i][role] = s.Recipient()
			policies[role] = append(policies[role], s.Recipient())
		}
	}
	caRoot, err := os.MkdirTemp(filepath.Join(project, ".work"), "dual-ca-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(caRoot); err != nil {
			t.Error(err)
		}
	})
	if e := os.Rename(online, filepath.Join(caRoot, "online")); e != nil {
		t.Fatal(e)
	}
	online = filepath.Join(caRoot, "online")
	caCert, caKey := pair("ca.dual.test", pkidomain.ServerAuth)
	lab.startCA(t, caRoot, caCert, caKey)
	images := map[string]string{}
	for role, mode := range Modes {
		images[role] = prepareDocker(t, "image", "inspect", "gatebeam-"+mode+":local", "--format", "{{.Id}}")
	}
	for i := 0; i < 2; i++ {
		label := []string{"a", "b"}[i]
		name := run + "-" + label
		dir := filepath.Join(root, label)
		if e = os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		// Owned lab bridges must not overlap Docker's automatic 172/192 pools:
		// an earlier or concurrent fixture may legitimately occupy those pools.
		mainBase := []string{"10.254.249.", "10.254.251."}[i]
		queryBase := []string{"10.254.250.", "10.254.252."}[i]
		vm := fmt.Sprintf("10.254.248.%d", 20+i)
		peer := fmt.Sprintf("10.254.248.%d", 21-i)
		node := &Node{Info: domain.NodeDeployment{Node: domain.NodeRef{ID: []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}[i], Epoch: 1}, PrivateAddress: vm, PeerAddress: peer, StoragePrefix: name, Instance: "projects/owned/zones/us-west1-c/instances/" + name, InstanceGroup: "projects/owned/zones/us-west1-c/instanceGroups/" + name, PublicBackend: "projects/owned/regions/us-west1/backendServices/entry", PrivateBackend: "projects/owned/regions/us-west1/backendServices/ca", ComposeFile: filepath.Join(dir, "compose.yaml"), EnvironmentFile: filepath.Join(dir, "node.env"), Roles: map[string]domain.RoleDeployment{}}, ComposeFile: filepath.Join(dir, "compose.yaml"), Router: name + "-router", Secrets: map[string]string{}, Configs: map[string]bootstrap.Config{}}
		lab.Nodes = append(lab.Nodes, node)
		logins := rolefixture.RuntimeRoles(t, pool, stopConsumers)
		for _, login := range logins {
			consumerLogins = append(consumerLogins, login.Name)
		}
		schema := pool.Config().ConnConfig.RuntimeParams["search_path"]
		write := func(role, file string, raw []byte) {
			p := filepath.Join(node.Secrets[role], file)
			if e := os.WriteFile(p, raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
		for role, mode := range Modes {
			secret := filepath.Join(dir, mode)
			if e = os.Mkdir(secret, 0700); e != nil {
				t.Fatal(e)
			}
			node.Secrets[role] = secret
			node.Info.Roles[role] = domain.RoleDeployment{Image: "registry.example/gatebeam/" + mode + "@" + images[role], Protocol: 1, ConfigFile: filepath.Join(secret, mode+".json"), HealthPort: HealthPorts[role], ControlVolume: name + "-" + role + "-control"}
			if role != "log-query" {
				u := &url.URL{Scheme: "postgres", User: url.UserPassword(logins[mode].Name, logins[mode].Password), Host: mainBase + "4:5432", Path: pool.Config().ConnConfig.Database}
				u.RawQuery = url.Values{"sslmode": {"disable"}, "search_path": {schema}}.Encode()
				write(role, "database", []byte(u.String()))
			}
		}
		for role, field := range map[string]string{"management": "api", "nginx": "leaf"} {
			raw, _ := os.ReadFile(keys[i][field])
			write(role, "identity.agekey", raw)
		}
		for role, file := range map[string]string{"provider": "provider.agekey", "notification": "notification.agekey"} {
			raw, _ := os.ReadFile(keys[i][role])
			write("background-jobs", file, raw)
		}
		for _, role := range []string{"nginx", "management", "background-jobs"} {
			write(role, "roots.pem", trust)
		}
		issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})
		rootBlock, _ := pem.Decode(trust)
		rf := fmt.Sprintf("%x", sha256.Sum256(rootBlock.Bytes))
		inf := string(issuer.Metadata().ID)
		statusProfiles, err := json.Marshal([]map[string]any{{
			"id": "external-ca", "fingerprints": []string{rf, inf},
			"crl_urls":         map[string]string{rf: caStatusOrigin + "/crl/root.der", inf: caStatusOrigin + "/crl/" + inf + ".der"},
			"ocsp_urls":        map[string]string{rf: caStatusOrigin + "/ocsp", inf: caStatusOrigin + "/ocsp"},
			"allowed_networks": []string{"10.254.248.15/32"}, "resolver_servers": []string{"127.0.0.11:53"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []string{"nginx", "management"} {
			write(role, "ca-status-trust.pem", append(append([]byte{}, trust...), issuerPEM...))
			write(role, "ca-status-profiles.json", statusProfiles)
		}
		write("nginx", "management.pem", mgmtCert)
		write("nginx", "management.key", mgmtKey)
		write("management", "management.pem", mgmtCert)
		apiCert, apiKey := pair("management-api.dual.test", pkidomain.ServerAuth)
		write("management", "api.pem", apiCert)
		write("management", "api.key", apiKey)
		write("management", "api-client-trust.pem", append(append([]byte{}, trust...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...))
		crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, issuer.Certificate, issuer.Signer)
		if e != nil {
			t.Fatal(e)
		}
		rootCRL, e := os.ReadFile(filepath.Join(online, "root.crl.der"))
		if e != nil {
			t.Fatal(e)
		}
		write("management", "api-client.crl", append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rootCRL})...))
		clientCert, clientKey := pair("gateway-"+label+".dual.test", pkidomain.ClientAuth)
		write("nginx", "api-client.pem", clientCert)
		write("nginx", "api-client.key", clientKey)
		write("log-query", "r2.json", []byte(`{"endpoint":"http://127.0.0.1:1","bucket":"owned","region":"us-east-1","AccessKey":"owned-read","SecretKey":"owned-read"}`))
		roleIP := map[string]string{"nginx": mainBase + "2", "management": mainBase + "3", "background-jobs": mainBase + "5", "log-query": queryBase + "2"}
		common := func(role string) bootstrap.Config {
			return bootstrap.Config{Environment: "production", Mode: Modes[role], RuntimeProtocol: 1, NodeID: node.Info.Node.ID, NodeEpoch: 1, ImageDigest: images[role], HealthListen: roleIP[role] + ":9090", ControlSocket: "/run/control/control.sock", DrainSeconds: 1, EncryptionRecipients: policies}
		}
		edge := common("nginx")
		edge.CertificateStatusTrustFile = "/run/gatebeam/ca-status-trust.pem"
		edge.CertificateStatusProfilesFile = "/run/gatebeam/ca-status-profiles.json"
		edge.DatabaseFile = "/run/gatebeam/database"
		edge.EdgeRoot = "/var/lib/gatebeam"
		edge.CertificateIdentityFile = "/run/gatebeam/identity.agekey"
		edge.CertificateRecipient = own[i]["leaf"]
		edge.CertificateProviderRecipient = own[i]["provider"]
		edge.ManagementDomain = "management.dual.test"
		edge.ManagementCertificateFile = "/run/gatebeam/management.pem"
		edge.ManagementKeyFile = "/run/gatebeam/management.key"
		edge.ManagementTrustFile = "/run/gatebeam/roots.pem"
		edge.ManagementAPIAddress = vm + ":9443"
		edge.ManagementAPIPeerAddress = peer + ":9443"
		edge.ManagementAPIName = "management-api.dual.test"
		edge.ManagementAPITrustFile = "/run/gatebeam/roots.pem"
		edge.ManagementAPIClientCertificateFile = "/run/gatebeam/api-client.pem"
		edge.ManagementAPIClientKeyFile = "/run/gatebeam/api-client.key"
		edge.ManagementAPIStateFile = "/run/control/management-upstreams.json"
		edge.ACMEWebRoot = "/var/lib/gatebeam/acme"
		edge.ManagementACMEWebRoot = "/var/lib/gatebeam/management-acme"
		edge.ProtectedNetworks = []string{vm + "/32", peer + "/32", dbIP + "/32"}
		node.Configs["nginx"] = edge
		api := common("management")
		api.CertificateStatusTrustFile = "/run/gatebeam/ca-status-trust.pem"
		api.CertificateStatusProfilesFile = "/run/gatebeam/ca-status-profiles.json"
		api.DatabaseFile = "/run/gatebeam/database"
		api.IdentityFile = "/run/gatebeam/identity.agekey"
		api.APIListen = roleIP["management"] + ":9443"
		api.APIPrivateNetwork = mainBase + "0/29"
		api.APIOrigin = "https://management.dual.test"
		api.ManagementDomain = "management.dual.test"
		api.ManagementAddress = roleIP["nginx"] + ":8443"
		api.ManagementCertificateFile = "/run/gatebeam/management.pem"
		api.ManagementTrustFile = "/run/gatebeam/roots.pem"
		api.APITLSCertificateFile = "/run/gatebeam/api.pem"
		api.APITLSKeyFile = "/run/gatebeam/api.key"
		api.APITLSTrustFile = "/run/gatebeam/api-client-trust.pem"
		api.APITLSCRLFile = "/run/gatebeam/api-client.crl"
		api.APITLSStateFile = "/var/lib/gatebeam/capsules/api/tls-status.json"
		api.APITLSClientNames = []string{"gateway-a.dual.test", "gateway-b.dual.test"}
		api.CertificateRecipient = own[i]["leaf"]
		api.CertificateProviderRecipient = own[i]["provider"]
		api.NotificationRecipient = own[i]["notification"]
		api.CAOrigin = caOrigin
		api.CAStatusOrigin = caStatusOrigin
		api.CertificateACMETransportTrustFile = "/run/gatebeam/roots.pem"
		api.CAServerNames = []string{"service.dual.test", "management-api.dual.test", "ca.dual.test"}
		api.CAClientNames = []string{"gateway-a.dual.test", "gateway-b.dual.test"}
		node.Configs["management"] = api
		worker := common("background-jobs")
		worker.DatabaseFile = "/run/gatebeam/database"
		worker.ManagementAPIAddress = vm + ":9443"
		worker.CertificateProviderIdentityFile = "/run/gatebeam/provider.agekey"
		worker.CertificateRecipient = own[i]["leaf"]
		worker.NotificationIdentityFile = "/run/gatebeam/notification.agekey"
		worker.NotificationRecipient = own[i]["notification"]
		worker.LogDirectory = "/var/lib/gatebeam/logs"
		worker.LogSpoolDirectory = "/var/lib/gatebeam/spool"
		worker.QuerySocket = "/run/query/query.sock"
		worker.ACMEWebRoot = "/var/lib/gatebeam/acme"
		worker.CAOrigin = caOrigin
		worker.CertificateACMETransportTrustFile = "/run/gatebeam/roots.pem"
		node.Configs["background-jobs"] = worker
		query := common("log-query")
		query.QueryCredentialsFile = "/run/gatebeam/r2.json"
		query.QuerySocket = "/run/query/query.sock"
		query.QueryLocalDirectory = "/var/lib/gatebeam/spool"
		node.Configs["log-query"] = query
		for role, c := range node.Configs {
			raw, e := json.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			write(role, c.Mode+".json", raw)
		}
		var model map[string]any
		if e = yaml.Unmarshal(production, &model); e != nil {
			t.Fatal(e)
		}
		volumes := model["volumes"].(map[string]any)
		for key := range volumes {
			volumes[key] = map[string]any{"name": name + "-" + key, "labels": map[string]string{"gatebeam.fixture.run": run}}
		}
		model["networks"] = map[string]any{"node-private": map[string]any{"ipam": map[string]any{"config": []any{map[string]any{"subnet": mainBase + "0/29"}}}}, "query-egress": map[string]any{"ipam": map[string]any{"config": []any{map[string]any{"subnet": queryBase + "0/29"}}}}, "vpc": map[string]any{"external": true, "name": network}}
		for role, value := range model["services"].(map[string]any) {
			service := value.(map[string]any)
			mode := Modes[role]
			service["image"] = "gatebeam-" + mode + ":local"
			service["restart"] = "no"
			delete(service, "ports")
			mounts := []string{}
			for _, v := range service["volumes"].([]any) {
				m := v.(string)
				if !strings.Contains(m, "GATEBEAM_SECRET_ROOT") {
					mounts = append(mounts, m)
				}
			}
			secretName := role + "-secret"
			volumes[secretName] = map[string]any{"name": name + "-" + secretName}
			mounts = append(mounts, secretName+":/run/gatebeam:ro", probe+":/capabilities:ro")
			if os.Getenv("GATEBEAM_COMPOSE_EXACT_IMAGES") != "1" {
				mounts = append(mounts, binary+":/usr/local/bin/gatebeam:ro")
				if role != "log-query" {
					mounts = append(mounts, admin+":/usr/local/bin/gatebeam-admin:ro")
				}
			}
			service["volumes"] = mounts
			if role == "log-query" {
				service["networks"] = map[string]any{"query-egress": map[string]any{"ipv4_address": roleIP[role]}}
			} else {
				service["networks"] = map[string]any{"node-private": map[string]any{"ipv4_address": roleIP[role]}, "vpc": map[string]any{}}
			}
		}
		raw, e := yaml.Marshal(model)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(node.ComposeFile, raw, 0600); e != nil {
			t.Fatal(e)
		}
		// Register before starting any consumer; a partial startup must also
		// quiesce every already-created peer before database role cleanup.
		consumers = append(consumers, node)
		routes := map[string]string{"0.0.0.0:80": roleIP["nginx"] + ":8080", "0.0.0.0:443": roleIP["nginx"] + ":8443", "0.0.0.0:9443": roleIP["management"] + ":9443", mainBase + "4:5432": "database:5432"}
		for role, port := range HealthPorts {
			routes["0.0.0.0:"+fmt.Sprint(port)] = roleIP[role] + ":9090"
		}
		routeFile := filepath.Join(dir, "routes.json")
		raw, _ = json.Marshal(routes)
		os.WriteFile(routeFile, raw, 0444)
		routerArgs := []string{"create", "--name", node.Router, "--label", "gatebeam.fixture.run=" + run, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--sysctl", "net.ipv4.ip_unprivileged_port_start=0", "--network", network, "--ip", vm, "--network-alias", "gateway-" + label + ".dual.test", "--mount", "type=bind,src=" + probe + ",dst=/router.test,readonly", "-e", "GATEBEAM_TEST_TCP_ROUTES=env", "-e", "GATEBEAM_TEST_TCP_ROUTES_JSON=" + string(raw), "--entrypoint", "/router.test"}
		for _, port := range []int{80, 443, 9443, 8444, 8081, 19091, 19092, 19093, 19094, 19095} {
			routerArgs = append(routerArgs, "-p", "127.0.0.1::"+fmt.Sprint(port))
		}
		routerArgs = append(routerArgs, "gatebeam-edge:local")
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), cleanupBudget(25*time.Second))
			defer cancel()
			exec.CommandContext(ctx, "docker", "rm", "-f", node.Router).Run()
			if e := exec.CommandContext(ctx, "docker", "compose", "-p", name, "-f", node.ComposeFile, "down", "--volumes", "--remove-orphans", "--timeout", "2").Run(); e != nil {
				t.Error("owned node Compose cleanup failed", e)
			}
		})
		if i == 0 {
			routerArgs = append(routerArgs[:1], append([]string{"--network-alias", "management-api.dual.test"}, routerArgs[1:]...)...)
		}
		prepareDocker(t, routerArgs...)
		node.prepareCompose(t, "create", "--no-build")
		prepareDocker(t, "network", "connect", "--ip", mainBase+"4", name+"_node-private", node.Router)
		prepareDocker(t, "network", "connect", "--ip", queryBase+"3", name+"_query-egress", node.Router)
		prepareDocker(t, "start", node.Router)
		initArgs := []string{"run", "--rm", "--user", "0:0", "--read-only", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE"}
		for class := range volumes {
			initArgs = append(initArgs, "-v", name+"-"+class+":/owned/"+class)
		}
		initArgs = append(initArgs, "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "for d in /owned/*; do chmod 700 \"$d\"; chown 101:101 \"$d\"; done; chmod 700 /owned/edge-runtime/releases")
		prepareDocker(t, initArgs...)
		for role, source := range node.Secrets {
			seed := name + "-seed-" + role
			prepareDocker(t, "create", "--name", seed, "--network", "none", "-v", name+"-"+role+"-secret:/dest", "gatebeam-edge:local")
			prepareDocker(t, "cp", source+"/.", seed+":/dest")
			prepareDocker(t, "rm", seed)
			prepareDocker(t, "run", "--rm", "--user", "0:0", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE", "-v", name+"-"+role+"-secret:/dest", "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "chmod 700 /dest; chmod 600 /dest/*; chown -R 101:101 /dest")
		}
		node.admin(t, "prepare-management", cleanupBudget(25*time.Second))
		previewBudget := cleanupBudget(20 * time.Second)
		ctx, cancel := context.WithTimeout(t.Context(), previewBudget)
		previewStarted := time.Now()
		raw, e = exec.CommandContext(ctx, "docker", "compose", "-p", name, "-f", node.ComposeFile, "run", "--no-deps", "--rm", "-T", "nginx", "--config", "/run/gatebeam/edge.json", "--preview-edge").Output()
		// Capture the operation context before our own cancellation, so cleanup
		// cannot be mistaken for the cause of a failed preview.
		previewContextError := ctx.Err()
		cancel()
		if e != nil {
			t.Fatalf("owned enrollment preview failed: class=%s elapsed=%s command_budget=%s command_context=%v test_context=%v", previewFailureClass(e), time.Since(previewStarted), previewBudget, previewContextError, t.Context().Err())
		}
		var preview struct {
			Artifact string `json:"artifact_id"`
		}
		if json.Unmarshal(raw, &preview) != nil || len(preview.Artifact) != 64 {
			t.Fatal("invalid owned enrollment preview")
		}
		bridge := map[string]string{}
		protocols := map[string]uint32{}
		for role := range Modes {
			bridge[role] = images[role]
			protocols[role] = 1
		}
		registration := nodes.NodeRegistration{Node: node.Info.Node, Principal: logins["edge"].Name, RolePrincipals: map[string]string{"background-jobs": logins["worker"].Name}, EncryptionRecipients: own[i], RuntimeProtocol: 1, BootFormat: 1, BootArtifactID: preview.Artifact, BridgeImages: bridge, RoleProtocols: protocols}
		if e = postgres.NewRunner(pool).Within(t.Context(), func(sc transaction.Scope) error {
			_, e := deployment.NewNodes().RegisterWithin(sc, registration)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		node.prepareCompose(t, "run", "--no-deps", "--rm", "-T", "nginx", "--config", "/run/gatebeam/edge.json", "--initialize-edge")
		node.prepareCompose(t, "start", "nginx", "management", "background-jobs", "log-query")
		rootPool := x509.NewCertPool()
		rootPool.AppendCertsFromPEM(trust)
		node.PublicClient = fixtureTLSClient(rootPool, "management.dual.test", node.Port(t, 443), nil)
		pair, e := tls.X509KeyPair(clientCert, clientKey)
		if e != nil {
			t.Fatal(e)
		}
		node.APIClient = fixtureTLSClient(rootPool, "management-api.dual.test", node.Port(t, 9443), &pair)
		node.CAAddress = lab.CAAddress
		node.CAClient = fixtureTLSClient(rootPool, "ca.dual.test", lab.CAAddress, nil)
	}
	lab.Activate(t)
	verifyRoleBudgets(t, lab)
	return lab
}
