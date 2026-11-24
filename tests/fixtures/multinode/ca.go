//go:build integration

package multinode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gatebeam/internal/modules/pki/domain"
)

const caOrigin = "https://ca.dual.test:8444"
const caStatusOrigin = "http://ca.dual.test:8081"

func (l *Lab) startCA(t testing.TB, root string, cert, key []byte) {
	t.Helper()
	l.CADirectory = root
	l.CAContainer = l.Run + "-ca"
	dbContainer := l.Run + "-ca-db"
	prepareDocker(t, "run", "-d", "--name", dbContainer, "--network", l.Network, "--network-alias", "ca-database",
		"--label", "gatebeam.fixture.run="+l.Run, "--memory", "512m", "--cpus", "1", "--pids-limit", "64",
		"-e", "POSTGRES_PASSWORD=test-only", "-e", "POSTGRES_DB=authority",
		"postgres:18.6@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4")
	t.Cleanup(func() { CleanupDocker(t, "rm", "-fv", dbContainer) })
	prepareDocker(t, "exec", dbContainer, "sh", "-ec", "for i in $(seq 1 25); do pg_isready -h 127.0.0.1 -U postgres -d authority && exit 0; sleep 1; done; exit 1")
	prepareDocker(t, "exec", dbContainer, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE owned_ca_runtime LOGIN PASSWORD 'test-only'; CREATE ROLE owned_ca_admin LOGIN PASSWORD 'test-only';")

	for file, raw := range map[string][]byte{
		"owner.dsn":   []byte("postgres://postgres:test-only@ca-database:5432/authority?sslmode=disable"),
		"runtime.dsn": []byte("postgres://owned_ca_runtime:test-only@ca-database:5432/authority?sslmode=disable"),
		"admin.dsn":   []byte("postgres://owned_ca_admin:test-only@ca-database:5432/authority?sslmode=disable"),
		"tls.pem":     cert, "tls.key": key,
	} {
		l.caFile(t, file, raw)
	}
	l.caCommand(t, "migrate", "-database-file", "/ca/owner.dsn")
	l.caCommand(t, "migrate-roles", "-database-file", "/ca/owner.dsn")
	prepareDocker(t, "exec", dbContainer, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "GRANT gatebeam_ca_runtime TO owned_ca_runtime; GRANT gatebeam_ca_admin TO owned_ca_admin; REVOKE CONNECT ON DATABASE authority FROM PUBLIC; GRANT CONNECT ON DATABASE authority TO owned_ca_runtime, owned_ca_admin;")
	recipient, err := os.ReadFile(filepath.Join(root, "online", "recipient.txt"))
	if err != nil {
		t.Fatal(err)
	}
	servers := []string{"management-api.dual.test", "service.dual.test"}
	clients := []string{"gateway-a.dual.test", "gateway-b.dual.test"}
	raw, err := json.Marshal(map[string]any{
		"database_file": "/ca/runtime.dsn", "listen": "10.254.248.15:8444", "origin": caOrigin,
		"status_listen": "10.254.248.15:8081", "status_origin": caStatusOrigin,
		"tls_certificate_file": "/ca/tls.pem", "tls_key_file": "/ca/tls.key",
		"issuer_file": "/ca/online/issuer.pem", "root_file": "/ca/online/root.pem",
		"signer_file": "/ca/online/issuer.age", "identity_file": "/ca/online/identity.agekey",
		"root_crl_file": "/ca/online/root.crl.der", "root_ocsp_certificate_file": "/ca/online/root-ocsp.pem",
		"root_ocsp_signer_file": "/ca/online/root-ocsp.age",
		"server_names":          servers, "client_names": clients, "validation_networks": []string{"10.254.248.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	l.caFile(t, "serve.json", raw)
	raw, err = json.Marshal(map[string]any{
		"database_file": "/ca/admin.dsn", "origin": caOrigin, "recipient": strings.TrimSpace(string(recipient)),
		"server_names": servers, "client_names": clients,
	})
	if err != nil {
		t.Fatal(err)
	}
	l.caFile(t, "admin.json", raw)
	prepareDocker(t, "run", "-d", "--name", l.CAContainer, "--network", l.Network, "--network-alias", "ca.dual.test",
		"--ip", "10.254.248.15", "-p", "127.0.0.1::8444", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--mount", "type=bind,src="+root+",dst=/ca,readonly", "gatebeam-ca:local", "serve", "-config", "/ca/serve.json")
	t.Cleanup(func() { CleanupDocker(t, "rm", "-fv", l.CAContainer) })
	l.CAAddress = prepareDocker(t, "port", l.CAContainer, "8444/tcp")
}

func (l *Lab) RestartCA(t testing.TB) {
	t.Helper()
	Docker(t, "start", l.CAContainer)
	// Docker allocates another loopback port when a container starts again.
	l.CAAddress = Docker(t, "port", l.CAContainer, "8444/tcp")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(l.Trust) {
		t.Fatal("fixture CA trust")
	}
	client := fixtureTLSClient(pool, "ca.dual.test", l.CAAddress, nil)
	for _, node := range l.Nodes {
		node.CAAddress = l.CAAddress
		node.CAClient = client
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	var lastError error
	var lastStatus int
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, caOrigin+"/acme/server/directory", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		lastError = err
		if err == nil {
			lastStatus = resp.StatusCode
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	t.Fatal("independent CA did not resume serving ACME after restart", "address", l.CAAddress,
		"last_status", lastStatus, "last_error", lastError, "logs", Docker(t, "logs", "--tail", "8", l.CAContainer))
}

func (l *Lab) caFile(t testing.TB, name string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(l.CADirectory, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func (l *Lab) caCommand(t testing.TB, args ...string) string {
	t.Helper()
	return prepareDocker(t, append([]string{"run", "--rm", "--network", l.Network, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--mount", "type=bind,src=" + l.CADirectory + ",dst=/ca", "gatebeam-ca:local"}, args...)...)
}

func (l *Lab) caEAB(t testing.TB, name string, usage domain.Usage) []byte {
	t.Helper()
	directory := "server"
	if usage == domain.ClientAuth {
		directory = "client"
	}
	var grant struct{ ID string }
	raw := l.caCommand(t, "authorize", "-config", "/ca/admin.json", "-directory", directory, "-names", name, "-expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	if json.Unmarshal([]byte(raw), &grant) != nil || grant.ID == "" {
		t.Fatal("external CA grant missing")
	}
	file := "eab-" + grant.ID + ".json"
	l.caCommand(t, "issue-eab", "-config", "/ca/admin.json", "-grant", grant.ID, "-output", "/ca/"+file)
	out, err := os.ReadFile(filepath.Join(l.CADirectory, file))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (l *Lab) RevokeClient(t testing.TB, cert *x509.Certificate) {
	t.Helper()
	l.caCommand(t, "revoke", "-config", "/ca/admin.json", "-issuer", string(l.TestIssuer.Metadata().ID), "-serial", fmt.Sprintf("%040x", cert.SerialNumber), "-reason", "1")
}

func (l *Lab) UseRenewedClient(t testing.TB, node *Node) *x509.Certificate {
	t.Helper()
	// Read only public certificate bytes from the running gateway.
	container := node.Compose(t, "ps", "-q", "nginx")
	proofFile := filepath.Join(node.Secrets["nginx"], "observed-client.pem")
	Docker(t, "cp", container+":/var/lib/gatebeam/capsules/edge/renewed-tls.pem", proofFile)
	cert, err := os.ReadFile(proofFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(node.Secrets["nginx"], "api-client.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	tr := node.APIClient.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{pair}
	node.APIClient.Transport = tr
	block, _ := pem.Decode(cert)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func (l *Lab) IssuedCertificateCount(t testing.TB) int {
	t.Helper()
	var issued struct {
		Certificates []json.RawMessage `json:"certificates"`
	}
	if err := json.Unmarshal([]byte(l.caCommand(t, "inspect", "-config", "/ca/admin.json")), &issued); err != nil {
		t.Fatal("read independent CA certificate inventory:", err)
	}
	return len(issued.Certificates)
}
