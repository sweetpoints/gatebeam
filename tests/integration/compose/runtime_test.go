//go:build integration

package compose_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/deployment/application/nodes"
	deploydomain "gatebeam/internal/modules/deployment/domain"
	pkiapp "gatebeam/internal/modules/pki/application"
	pkidomain "gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/platform/bootstrap"
	platformpg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	rolefixture "gatebeam/tests/fixtures/deployment"
	labfixture "gatebeam/tests/fixtures/multinode"
	"go.yaml.in/yaml/v3"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if labfixture.ProcessMain() {
		return
	}
	os.Exit(m.Run())
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("owned compose docker %s: %v %s", args[0], e, b)
	}
	return strings.TrimSpace(string(b))
}
func TestBootstrapCreatesConfirmedMinimalBundle(t *testing.T) {
	binary := os.Getenv("GATEBEAM_COMPOSE_PROBE_BINARY")
	if binary == "" {
		t.Fatal("fresh native capability probe required")
	}
	_, source, _, _ := runtime.Caller(0)
	project := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
	base, e := os.ReadFile(filepath.Join(project, "compose.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = yaml.Unmarshal(base, &cfg); e != nil {
		t.Fatal(e)
	}
	services := cfg["services"].(map[string]any)
	// Database is fixture-owned and never part of the production declaration.
	services["postgres"] = map[string]any{"image": "postgres:18.6@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4", "environment": map[string]any{"POSTGRES_DB": "gatebeam", "POSTGRES_USER": "gatebeam", "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password"}, "networks": map[string]any{"node-private": map[string]any{"ipv4_address": "172.31.0.4"}}, "mem_limit": "768m", "pids_limit": 128}
	cfg["volumes"].(map[string]any)["edge-postgres"] = nil

	serviceByRole := map[string]string{"edge": "nginx", "api": "management", "worker": "background-jobs", "query-worker": "log-query", "postgres": "postgres"}
	roleByService := map[string]string{}
	for role, service := range serviceByRole {
		roleByService[service] = role
	}
	volumes := cfg["volumes"].(map[string]any)
	for name := range volumes {
		volumes[name] = nil
	} // fresh, test-owned and disposable

	root := t.TempDir()
	name := fmt.Sprintf("gatebeam-compose-%d", time.Now().UnixNano())
	path := filepath.Join(root, "compose.yaml")
	// The exact maintained service resource/capability/network topology is used.
	// Only local image references, owned fixture secrets and ephemeral host ports
	// differ. Dedicated fixed subnets must be free; Compose refuses collisions.
	for service, value := range services {
		role, ok := roleByService[service]
		if !ok {
			t.Fatalf("unexpected runtime service %s", service)
		}
		s := value.(map[string]any)
		if _, ok := s["build"]; ok {
			t.Fatalf("%s must use a prebuilt image", service)
		}
		if _, ok := s["profiles"]; ok {
			t.Fatalf("%s must be a default runtime service", service)
		}
		s["restart"] = "no"
		delete(s, "ports")
		if role == "postgres" {
			s["ports"] = []string{"127.0.0.1::5432"}
			// Docker does not publish ports for an internal-only network. This
			// fixture-only bridge allows host schema/role setup; production DB
			// remains attached exclusively to its internal database network.
			cfg["networks"].(map[string]any)["fixture-control"] = map[string]any{}
			s["networks"].(map[string]any)["fixture-control"] = map[string]any{}
			s["volumes"] = []string{name + "-postgres-secret:/run/secrets:ro", "edge-postgres:/var/lib/postgresql"}
			volumes[name+"-postgres-secret"] = nil
			continue
		}
		image := role
		if role == "query-worker" {
			image = "query"
		}
		s["image"] = "gatebeam-" + image + ":local"
		if role == "edge" {
			s["ports"] = []string{"127.0.0.1::8443", "127.0.0.1::8080"}
		}
		mounts := []string{name + "-" + role + "-secret:/run/gatebeam:ro", binary + ":/capabilities:ro"}
		if gateway := os.Getenv("GATEBEAM_COMPOSE_GATEWAY_BINARY"); gateway != "" && os.Getenv("GATEBEAM_COMPOSE_EXACT_IMAGES") != "1" {
			mounts = append(mounts, gateway+":/usr/local/bin/gatebeam:ro")
			if admin := os.Getenv("GATEBEAM_COMPOSE_ADMIN_BINARY"); admin != "" && role != "query-worker" {
				mounts = append(mounts, admin+":/usr/local/bin/gatebeam-admin:ro")
			}
		}
		for _, entry := range s["volumes"].([]any) {
			v := entry.(string)
			if !strings.Contains(v, "GATEBEAM_SECRET_ROOT") {
				mounts = append(mounts, v)
			}
		}
		s["volumes"] = mounts
		volumes[name+"-"+role+"-secret"] = nil
	}
	body, e := yaml.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	compose := func(args ...string) string {
		t.Helper()
		return docker(t, append([]string{"compose", "-p", name, "-f", path}, args...)...)
	}
	// Register cleanup first: role/schema cleanup runs while this DB is alive.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		exec.CommandContext(ctx, "docker", "compose", "-p", name, "-f", path, "down", "--volumes", "--remove-orphans", "--timeout", "2").Run()
	})
	write := func(dir, file string, b []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, file), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	dirs := map[string]string{}
	for _, service := range []string{"postgres", "api", "edge", "worker", "query-worker"} {
		dir := filepath.Join(root, service)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		dirs[service] = dir
	}
	write(dirs["postgres"], "postgres-password", []byte("owned-compose-password"))
	compose("create", "--no-build", "postgres", "nginx", "management", "background-jobs", "log-query")
	seed := func(service string) {
		t.Helper()
		logical := name + "-" + service + "-secret"
		volume := name + "_" + logical
		docker(t, "run", "--rm", "--user", "0:0", "--read-only", "--network", "none", "--memory", "32m", "--cpus", ".5", "--pids-limit", "16", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges:true", "--mount", "type=bind,src="+dirs[service]+",dst=/seed,readonly", "--mount", "type=volume,src="+volume+",dst=/dest", "--entrypoint", "sh", "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "-ec", "cp /seed/* /dest/; chmod 700 /dest; chmod 600 /dest/*; chown -R 101:101 /dest")
	}
	seed("postgres")
	compose("start", "postgres")
	preparationFactor := time.Duration(1)
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		preparationFactor = 12
	}
	until := time.Now().Add(preparationFactor * 12 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), preparationFactor*time.Second)
		err := exec.CommandContext(ctx, "docker", "compose", "-p", name, "-f", path, "exec", "-T", "postgres", "pg_isready", "-h", "127.0.0.1", "-U", "gatebeam").Run()
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("owned Compose postgres readiness")
		}
		time.Sleep(100 * time.Millisecond)
	}
	port := compose("port", "postgres", "5432")

	t.Setenv("GATEBEAM_TEST_DATABASE_URL", "postgres://gatebeam:owned-compose-password@"+port+"/gatebeam?sslmode=disable")
	db := testkit.Postgres(t)
	roles := rolefixture.RuntimeRoles(t, db)
	schema := db.Config().ConnConfig.RuntimeParams["search_path"]
	for _, service := range []string{"api", "edge", "worker"} {
		dsn := &url.URL{Scheme: "postgres", User: url.UserPassword(roles[service].Name, roles[service].Password), Host: "172.31.0.4:5432", Path: "gatebeam"}
		q := url.Values{"sslmode": {"disable"}, "search_path": {schema}}
		dsn.RawQuery = q.Encode()
		write(dirs[service], "database", []byte(dsn.String()))
	}
	offline := filepath.Join(root, "offline-root")
	online := filepath.Join(root, "online")
	if e = (pkicrypto.Bootstrapper{}).Generate(t.Context(), pkiapp.BootstrapCommand{RootDirectory: offline, OnlineDirectory: online, RootName: "owned Compose root", IntermediateName: "owned Compose intermediate", StatusOrigin: "http://ca.test:8081"}); e != nil {
		t.Fatal(e)
	}
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	roots, e := os.ReadFile(filepath.Join(online, "root.pem"))
	if e != nil {
		t.Fatal(e)
	}
	pairFor := func(host string, purpose pkidomain.Usage) ([]byte, []byte) {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, key)
		if e != nil {
			t.Fatal(e)
		}
		policy, _ := pkidomain.NewPolicy([]string{host}, purpose)
		der, e := issuer.SignCSR(csr, policy, []string{host}, big.NewInt(time.Now().UnixNano()), time.Now(), time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		private, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...)
		return cert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	pair := func(host string) ([]byte, []byte) { return pairFor(host, pkidomain.ServerAuth) }
	managementCert, managementKey := pair("management.test")
	apiCert, apiKey := pair("management-api.test")
	clientCert, clientKey := pairFor("gateway-a.test", pkidomain.ClientAuth)
	write(dirs["api"], "api-tls.pem", apiCert)
	write(dirs["api"], "api-tls.key", apiKey)
	write(dirs["edge"], "api-client.pem", clientCert)
	write(dirs["edge"], "api-client.key", clientKey)
	for _, service := range []string{"api", "edge"} {
		write(dirs[service], "management.pem", managementCert)
		write(dirs[service], "roots.pem", roots)
	}
	write(dirs["edge"], "management.key", managementKey)
	if e = secrets.EnsureIdentity(filepath.Join(dirs["api"], "identity.agekey")); e != nil {
		t.Fatal(e)
	}
	if e = secrets.EnsureIdentity(filepath.Join(dirs["edge"], "leaf.agekey")); e != nil {
		t.Fatal(e)
	}
	if e = secrets.EnsureIdentity(filepath.Join(dirs["worker"], "provider.agekey")); e != nil {
		t.Fatal(e)
	}
	leaf, e := secrets.New(filepath.Join(dirs["edge"], "leaf.agekey"))
	if e != nil {
		t.Fatal(e)
	}
	provider, e := secrets.New(filepath.Join(dirs["worker"], "provider.agekey"))
	if e != nil {
		t.Fatal(e)
	}
	configs := map[string]bootstrap.Config{
		"edge":         {Environment: "production", Mode: "edge", DatabaseFile: "/run/gatebeam/database", CertificateIdentityFile: "/run/gatebeam/leaf.agekey", CertificateProviderRecipient: provider.Recipient(), EdgeRoot: "/var/lib/gatebeam", ManagementDomain: "management.test", ManagementAPIAddress: "172.31.0.3:8080", ManagementCertificateFile: "/run/gatebeam/management.pem", ManagementKeyFile: "/run/gatebeam/management.key", ManagementTrustFile: "/run/gatebeam/roots.pem", ProtectedNetworks: []string{"172.31.0.0/29", "172.31.0.0/29"}, ACMEWebRoot: "/var/lib/gatebeam/acme"},
		"api":          {Environment: "production", Mode: "api", DatabaseFile: "/run/gatebeam/database", IdentityFile: "/run/gatebeam/identity.agekey", APIListen: "172.31.0.3:8080", APIPrivateNetwork: "172.31.0.0/29", APIOrigin: "https://management.test", ManagementDomain: "management.test", ManagementAddress: "172.31.0.2:8443", ManagementCertificateFile: "/run/gatebeam/management.pem", ManagementTrustFile: "/run/gatebeam/roots.pem"},
		"worker":       {Environment: "production", Mode: "worker", DatabaseFile: "/run/gatebeam/database", ManagementAPIAddress: "172.31.0.3:8080", CertificateProviderIdentityFile: "/run/gatebeam/provider.agekey", CertificateRecipient: leaf.Recipient(), ACMEWebRoot: "/var/lib/gatebeam/acme", LogDirectory: "/var/lib/gatebeam/logs", LogSpoolDirectory: "/var/lib/gatebeam/spool", QuerySocket: "/run/query/query.sock"},
		"query-worker": {Environment: "production", Mode: "query", QueryCredentialsFile: "/run/gatebeam/objectstore.json", QuerySocket: "/run/query/query.sock", QueryLocalDirectory: "/var/lib/gatebeam/spool"},
	}
	node := deploydomain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	image := "sha256:" + strings.Repeat("a", 64)
	images := map[string]string{}
	protocols := map[string]uint32{}
	for _, name := range []string{"nginx", "management", "background-jobs", "log-query"} {
		images[name] = image
		protocols[name] = 1
	}
	registration := nodes.NodeRegistration{Node: node, Principal: roles["edge"].Name, RuntimeProtocol: 1, BootFormat: 1, BootArtifactID: strings.Repeat("b", 64), BridgeImages: images, RoleProtocols: protocols, EncryptionRecipients: map[string]string{"leaf": leaf.Recipient()}, RolePrincipals: map[string]string{"background-jobs": roles["worker"].Name}}

	edgeConfig := configs["edge"]
	edgeConfig.RuntimeProtocol = 1
	edgeConfig.NodeID = node.ID
	edgeConfig.NodeEpoch = node.Epoch
	edgeConfig.ImageDigest = image
	edgeConfig.CertificateRecipient = leaf.Recipient()
	edgeConfig.ManagementAPIAddress = "172.31.0.3:9443"
	edgeConfig.ManagementAPIPeerAddress = "172.31.0.4:9443"
	edgeConfig.ManagementAPIName = "management-api.test"
	edgeConfig.ManagementAPITrustFile = "/run/gatebeam/roots.pem"
	edgeConfig.ManagementAPIClientCertificateFile = "/run/gatebeam/api-client.pem"
	edgeConfig.ManagementAPIClientKeyFile = "/run/gatebeam/api-client.key"
	edgeConfig.ManagementAPIStateFile = "/run/control/management-upstreams.json"
	configs["edge"] = edgeConfig
	apiConfig := configs["api"]
	apiConfig.APIListen = "172.31.0.3:9443"
	apiConfig.APITLSCertificateFile = "/run/gatebeam/api-tls.pem"
	apiConfig.APITLSKeyFile = "/run/gatebeam/api-tls.key"
	apiConfig.APITLSTrustFile = "/run/gatebeam/roots.pem"
	apiConfig.APITLSClientNames = []string{"gateway-a.test", "gateway-b.test"}
	apiConfig.APITLSTrustFile = "/run/gatebeam/api-client-trust.pem"
	apiConfig.APITLSCRLFile = "/run/gatebeam/api-client.crl"
	apiConfig.APITLSStateFile = "/var/lib/gatebeam/capsules/api/tls-status.json"
	write(dirs["api"], "api-client-trust.pem", append(append([]byte{}, roots...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...))
	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, issuer.Certificate, issuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	rootCRL, e := os.ReadFile(filepath.Join(online, "root.crl.der"))
	if e != nil {
		t.Fatal(e)
	}
	write(dirs["api"], "api-client.crl", append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rootCRL})...))
	configs["api"] = apiConfig
	write(dirs["query-worker"], "objectstore.json", []byte(`{"endpoint":"http://127.0.0.1:1","bucket":"owned","region":"us-east-1","AccessKey":"owned","SecretKey":"owned"}`))
	if e := secrets.EnsureIdentity(filepath.Join(dirs["worker"], "notification.agekey")); e != nil {
		t.Fatal(e)
	}
	rolePolicy := secrets.RolePolicy{}
	for key, ref := range map[string][2]string{"api": {"api", "identity.agekey"}, "provider": {"worker", "provider.agekey"}, "notification": {"worker", "notification.agekey"}, "leaf": {"edge", "leaf.agekey"}} {
		identity, e := secrets.New(filepath.Join(dirs[ref[0]], ref[1]))
		if e != nil {
			t.Fatal(e)
		}
		rolePolicy[key] = []string{identity.Recipient()}
		registration.EncryptionRecipients[key] = identity.Recipient()
	}
	for service, config := range configs {
		if service != "query-worker" {
			config.EncryptionRecipients = rolePolicy
		}
		if service == "worker" {
			config.NotificationIdentityFile = "/run/gatebeam/notification.agekey"
			config.NotificationRecipient = rolePolicy["notification"][0]
		}
		config.RuntimeProtocol = 1
		config.NodeID = node.ID
		config.NodeEpoch = node.Epoch
		config.ImageDigest = image
		addresses := map[string]string{"edge": "172.31.0.2", "api": "172.31.0.3", "worker": "172.31.0.5", "query-worker": "172.29.0.2"}
		config.HealthListen = addresses[service] + ":9090"
		config.ControlSocket = "/run/control/control.sock"
		config.DrainSeconds = 2
		b, e := json.Marshal(config)
		if e != nil {
			t.Fatal(e)
		}
		file := config.Mode + ".json"
		write(dirs[service], file, b)
		seed(service)
	}
	for _, service := range []string{"nginx", "management", "background-jobs", "log-query", "api-capsules"} {
		volume := name + "_" + service + "-control"
		if service == "api-capsules" {
			volume = name + "_api-capsules"
		}
		docker(t, "run", "--rm", "--user", "0:0", "--read-only", "--network", "none", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--mount", "type=volume,src="+volume+",dst=/volume", "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "chmod 700 /volume; chown 101:101 /volume")
	}
	// Controlled fixture provisioning verifies the private retained volume mode.
	// This also exercises upgrades from an older image's 0755 empty volume.
	docker(t, "run", "--rm", "--user", "101:101", "--read-only", "--network", "none", "--cap-drop", "ALL", "--mount", "type=volume,src="+name+"_edge-runtime,dst=/volume", "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "chmod 700 /volume /volume/releases")
	compose("run", "--no-deps", "--rm", "-T", "--entrypoint", "/usr/local/bin/gatebeam-admin", "nginx", "--operation", "prepare-management", "--config", "/run/gatebeam/edge.json")
	// Preview compiles the management-only reference before registration, without
	// claiming the node has loaded it or creating its node authority.
	previewCtx, previewDone := context.WithTimeout(t.Context(), 15*time.Second)
	preview, e := exec.CommandContext(previewCtx, "docker", "compose", "-p", name, "-f", path, "run", "--no-deps", "--rm", "-T", "nginx", "--config", "/run/gatebeam/edge.json", "--preview-edge").Output()
	previewDone()
	if e != nil {
		t.Fatal("initial enrollment preview failed", e)
	}
	var reference struct {
		ArtifactID string `json:"artifact_id"`
	}
	if e = json.Unmarshal(preview, &reference); e != nil || len(reference.ArtifactID) != 64 {
		t.Fatal("invalid enrollment reference", e)
	}
	registration.BootArtifactID = reference.ArtifactID
	if e = platformpg.NewRunner(db).Within(t.Context(), func(sc transaction.Scope) error {
		_, e := deployment.NewNodes().RegisterWithin(sc, registration)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// A fresh disk never starts through the ordinary offline path.
	cold, done := context.WithTimeout(t.Context(), 15*time.Second)
	command := exec.CommandContext(cold, "docker", "compose", "-p", name, "-f", path, "run", "--no-deps", "--rm", "nginx", "--config", "/run/gatebeam/edge.json")
	if b, err := command.CombinedOutput(); err == nil || cold.Err() != nil {
		done()
		t.Fatal("fresh disk must fail promptly before serving", string(b), err)
	}
	done()
	compose("run", "--no-deps", "--rm", "nginx", "--config", "/run/gatebeam/edge.json", "--initialize-edge")
	proofCtx, proofDone := context.WithTimeout(t.Context(), 10*time.Second)
	proof, e := exec.CommandContext(proofCtx, "docker", "compose", "-p", name, "-f", path, "run", "--no-deps", "--rm", "-T", "--entrypoint", "/usr/local/bin/gatebeam-admin", "nginx", "--operation", "inspect-boot", "--config", "/run/gatebeam/edge.json").Output()
	proofDone()
	if e != nil {
		t.Fatal("confirmed native bundle proof unavailable", e)
	}
	var evidence struct{ ArtifactID string }
	if e = json.Unmarshal(proof, &evidence); e != nil || evidence.ArtifactID != reference.ArtifactID {
		t.Fatal("initialized bundle differs from enrollment reference", e)
	}
	compose("start", "nginx")
	address := compose("port", "nginx", "8443")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(roots)
	hc := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "management.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, addressIgnored string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}}
	get := func(route string) (int, []byte, error) {
		r, e := hc.Get("https://management.test" + route)
		if e != nil {
			return 0, nil, e
		}
		defer r.Body.Close()
		b, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		return r.StatusCode, b, e
	}
	until = time.Now().Add(8 * time.Second)
	for {
		status, b, e := get("/_gatebeam/ready")
		if e == nil && status == 200 && string(b) == "management-ready" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("native management bootstrap readiness")
		}
		time.Sleep(100 * time.Millisecond)
	}
	compose("start", "management", "background-jobs", "log-query")
	t.Cleanup(func() {
		if t.Failed() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			b, _ := exec.CommandContext(ctx, "docker", "compose", "-p", name, "-f", path, "logs", "--no-color", "--tail", "10", "management", "background-jobs", "nginx", "log-query").CombinedOutput()
			t.Log(string(b))
		}
	})
	// Initial management process preparation is an observer budget. The
	// gateway's independent offline bootstrap and recovery deadlines stay fixed.
	initialManagementWait := 8 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		initialManagementWait *= 12
	}
	until = time.Now().Add(initialManagementWait)
	for {
		status, b, e := get("/")
		if e == nil && status == 200 && strings.Contains(string(b), "/assets/") {
			break
		}
		if time.Now().After(until) {
			t.Fatal("real image management static bundle unavailable", status, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, service := range []string{"api", "edge", "worker", "query-worker"} {
		id := compose("ps", "-q", serviceByRole[service])
		if id == "" {
			t.Fatal("required Compose process absent", service)
		}
		if state := docker(t, "inspect", "--format", "{{.State.Running}}", id); state != "true" {
			t.Fatal("required Compose process exited", service)
		}
		denied := []string{"/var/run/docker.sock", "/offline-root/root-key.pem", "/run/gatebeam/root-key.pem"}
		switch service {
		case "api":
			denied = append(denied, "/run/gatebeam/issuer.age", "/run/gatebeam/leaf.agekey", "/run/gatebeam/provider.agekey", "/run/query/query.sock")
		case "edge":
			denied = append(denied, "/run/gatebeam/issuer.age", "/run/gatebeam/provider.agekey", "/run/query/query.sock")
		case "worker":
			denied = append(denied, "/run/gatebeam/issuer.age", "/run/gatebeam/leaf.agekey")
		case "query-worker":
			denied = append(denied, "/run/gatebeam/database", "/run/gatebeam/issuer.age", "tcp:172.31.0.4:5432")
		}
		args := append([]string{"exec", "-e", "GATEBEAM_CAPABILITY_PROBE=1", id, "/capabilities"}, denied...)
		docker(t, args...)
	}
	t.Log("actual maintained Compose topology: four gateway processes, native management TLS and restricted role capabilities")

}

func TestNegativeCapabilityProbeRejectsPresentUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gb-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "query.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], path)
	cmd.Env = append(os.Environ(), "GATEBEAM_CAPABILITY_PROBE=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("known-present Unix socket falsely reported denied: %s", output)
	}
	if ctx.Err() != nil {
		t.Fatal("probe timed out")
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("unexpected probe error: %v %s", err, output)
	}
}

func TestSocketAbsenceProbeClassifiesErrors(t *testing.T) {
	root := t.TempDir()
	ordinary := filepath.Join(root, "file")
	if e := os.WriteFile(ordinary, []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name, path string
		code       int
	}{{"missing", filepath.Join(root, "missing.sock"), 0}, {"not-directory", filepath.Join(ordinary, "query.sock"), 2}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], test.path)
			cmd.Env = append(os.Environ(), "GATEBEAM_CAPABILITY_PROBE=1")
			out, e := cmd.CombinedOutput()
			code := 0
			if e != nil {
				exit, ok := e.(*exec.ExitError)
				if !ok {
					t.Fatal(e)
				}
				code = exit.ExitCode()
			}
			if ctx.Err() != nil || code != test.code {
				t.Fatalf("unexpected probe classification %d want %d: %s %v", code, test.code, out, e)
			}
		})
	}
}
