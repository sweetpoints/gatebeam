//go:build integration

package edge_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	releasepg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/observability/application/ingest"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	logspool "gatebeam/internal/modules/observability/infrastructure/parquet"
	logpg "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	runtimefixture "gatebeam/tests/fixtures/deployment"
	pq "github.com/parquet-go/parquet-go"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This acceptance test runs the real production edge entrypoint, its real child
// Nginx, a separate API container and a PostgreSQL login outage confined to edge.
func TestI4EdgeManagementAndDatabaseOutage(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	binary := os.Getenv("GATEBEAM_I4_BINARY")
	dbContainer := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if binary == "" || dbContainer == "" {
		t.Fatal("run scripts/check-edge.sh supervisor: native binary and owned DB required")
	}
	root := t.TempDir()
	if e := os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	network := "gatebeam-i4-" + suffix
	edgeName := network + "-edge"
	apiName := network + "-api"
	command(t, "docker", "network", "create", "--internal", network)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(c, "docker", "network", "disconnect", network, dbContainer).Run()
		_ = exec.CommandContext(c, "docker", "network", "rm", network).Run()
	})
	subnet := command(t, "docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", network)
	prefix, e := netip.ParsePrefix(subnet)
	if e != nil {
		t.Fatal(e)
	}
	// Docker26 accepts fixed endpoints only on a user-configured subnet. Let
	// Docker select a conflict-free pool first, then explicitly reserve that
	// same pool for this owned network before attaching any containers.
	command(t, "docker", "network", "rm", network)
	command(t, "docker", "network", "create", "--internal", "--subnet", prefix.String(), network)
	edgeIP := prefix.Addr().Next().Next()
	apiIP := edgeIP.Next()
	dbIP := apiIP.Next()
	command(t, "docker", "network", "connect", "--ip", dbIP.String(), network, dbContainer)
	roles := runtimefixture.RuntimeRoles(t, p)
	role := roles["edge"].Name
	schema := p.Config().ConnConfig.RuntimeParams["search_path"]
	dsn, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	dsn.Host = net.JoinHostPort(dbIP.String(), "5432")
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	dsn.User = url.UserPassword(roles["api"].Name, roles["api"].Password)
	apiDSN := dsn.String()
	dsn.User = url.UserPassword(role, roles["edge"].Password)
	ca := newCA(t, "manually owned management CA")
	cert, key := ca.leaf(t, "management.test", false)

	edgeFiles := filepath.Join(root, "edge")
	apiFiles := filepath.Join(root, "api")
	stateDir := filepath.Join(root, "state")
	for _, dir := range []string{edgeFiles, apiFiles, stateDir} {
		if e = os.Mkdir(dir, 0755); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Chmod(stateDir, 0777); e != nil {
		t.Fatal(e)
	} // isolated test bind volume; product named volume belongs to UID101
	for dir, files := range map[string]map[string][]byte{
		edgeFiles: {"management.pem": cert, "management.key": key, "management-ca.pem": ca.pem, "edge-database": []byte(dsn.String())},
		apiFiles:  {"management.pem": cert, "management-ca.pem": ca.pem, "api-database": []byte(apiDSN)},
	} {
		for name, data := range files {
			if e = os.WriteFile(filepath.Join(dir, name), data, 0444); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e = secrets.EnsureIdentity(filepath.Join(apiFiles, "identity.agekey")); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(apiFiles, "identity.agekey"), 0444); e != nil {
		t.Fatal(e)
	}
	edgeCfg := bootstrap.Config{Environment: "production", Mode: "edge", DatabaseFile: "/fixture/edge-database", EdgeRoot: "/state", ManagementDomain: "management.test", ManagementAPIAddress: net.JoinHostPort(apiIP.String(), "8080"), ManagementCertificateFile: "/fixture/management.pem", ManagementKeyFile: "/fixture/management.key", ManagementTrustFile: "/fixture/management-ca.pem", ProtectedNetworks: []string{subnet}}
	apiCfg := bootstrap.Config{Environment: "production", Mode: "api", DatabaseFile: "/fixture/api-database", IdentityFile: "/fixture/identity.agekey", APIListen: net.JoinHostPort(apiIP.String(), "8080"), APIPrivateNetwork: subnet, APIOrigin: "https://management.test", ManagementDomain: "management.test", ManagementAddress: net.JoinHostPort(edgeIP.String(), "8443"), ManagementCertificateFile: "/fixture/management.pem", ManagementTrustFile: "/fixture/management-ca.pem"}
	apiCfg.HTTPSGatewayReady = true // negative readiness below must ignore this legacy declaration
	for name, cfg := range map[string]bootstrap.Config{"edge.json": edgeCfg, "api.json": apiCfg} {
		b, _ := json.Marshal(cfg)
		if e = os.WriteFile(filepath.Join(root, cfg.Mode, name), b, 0444); e != nil {
			t.Fatal(e)
		}
	}
	r := release.New(releasepg.New(), identifiers.Generator{})
	tx := postgres.NewRunner(p)
	siteID := "33333333-3333-4333-8333-333333333333"
	e = tx.Within(ctx, func(sc transaction.Scope) error {
		c, e := r.PrepareWithin(sc, release.PrepareInput{Snapshot: deploy.Snapshot{Version: "deployment/v1", Sites: []deploy.Site{{ID: siteID, Revision: 1, Config: deploy.SiteConfig{Enabled: true, Domains: []string{"route.test"}, Maintenance: deploy.MaintenancePolicy{Enabled: true, Status: 503, Message: "still-serving"}}}}}, SelectedSiteIDs: []string{siteID}, Expected: map[string]int64{"site:" + siteID: 1}})
		if e != nil {
			return e
		}
		if _, e = r.PublishWithin(sc, c.ID); e != nil {
			return e
		}
		return r.RecordVerifiedWithin(sc, c.ID, strings.Repeat("0", 64), "fixture-verified")
	})
	if e != nil {
		t.Fatal(e)
	}
	start := func(name, ip, config string, publish bool) {
		files := apiFiles
		if publish {
			files = edgeFiles
		}
		args := []string{"docker", "create", "--name", name, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--tmpfs", "/tmp:size=32m,mode=1777", "--mount", "type=bind,src=" + files + ",dst=/fixture,readonly", "--mount", "type=bind,src=" + binary + ",dst=/gatebeam,readonly", "--entrypoint", "/gatebeam"}
		if publish {
			args = append(args, "--network", "bridge", "--mount", "type=bind,src="+stateDir+",dst=/state")
			args = append(args, "-p", "127.0.0.1::8443", "-p", "127.0.0.1::8080")
		}
		if !publish {
			args = append(args, "--network", network, "--ip", ip)
		}
		args = append(args, image, "--config", "/fixture/"+config)
		command(t, args...)
		if publish {
			command(t, "docker", "network", "connect", "--ip", ip, network, name)
		}
		command(t, "docker", "start", name)
		t.Cleanup(func() {
			if t.Failed() {
				t.Log(command(t, "docker", "logs", name))
			}
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = exec.CommandContext(c, "docker", "rm", "-f", name).Run()
		})
	}
	start(edgeName, edgeIP.String(), "edge.json", true)
	tlsPort := strings.TrimPrefix(command(t, "docker", "port", edgeName, "8443/tcp"), "127.0.0.1:")
	httpPort := strings.TrimPrefix(command(t, "docker", "port", edgeName, "8080/tcp"), "127.0.0.1:")
	pool := caPool(ca.pem)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "management.test"}, DisableKeepAlives: true}}
	fetch := func(path string) (int, string, error) {
		req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+tlsPort+path, nil)
		req.Host = "management.test"
		resp, e := client.Do(req)
		if e != nil {
			return 0, "", e
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, string(b), e
	}
	await := func(path string) {
		deadline := time.Now().Add(12 * time.Second)
		for {
			status, _, e := fetch(path)
			if e == nil && status == 200 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("native HTTPS %s: %d %v", path, status, e)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	await("/_gatebeam/ready")
	start(apiName, apiIP.String(), "api.json", false)
	await("/readyz")
	if published := command(t, "docker", "port", apiName); published != "" {
		t.Fatalf("API was host-published: %s", published)
	}

	if _, e = os.Stat(filepath.Join(apiFiles, "management.key")); !os.IsNotExist(e) {
		t.Fatal("API received management private key")
	}
	other, _ := ca.leaf(t, "management.test", false)
	pin := filepath.Join(apiFiles, "management.pem")
	if e = os.Chmod(pin, 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(pin, other, 0444); e != nil {
		t.Fatal(e)
	}
	status, _, e := fetch("/readyz")
	if e != nil || status != 503 {
		t.Fatalf("legacy boolean bypassed measured TLS pin mismatch: %d %v", status, e)
	}
	if e = os.WriteFile(pin, cert, 0444); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(pin, 0444); e != nil {
		t.Fatal(e)
	}
	await("/readyz")
	master := command(t, "docker", "exec", edgeName, "cat", "/tmp/gatebeam-nginx.pid")
	t.Logf("real separate API/edge; edge parent PID 1; Nginx child PID %s; measured owned management TLS and API /readyz", master)
	route := func() {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+httpPort+"/safe/must-not-log/4111111111111111?token=must-not-log", strings.NewReader("must-not-log"))
		req.Header.Set("Authorization", "Bearer must-not-log")
		req.Header.Set("Cookie", "secret=must-not-log")
		req.Host = "route.test"
		c := &http.Client{Timeout: time.Second}
		resp, e := c.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode != 503 || string(b) != "still-serving" {
			t.Fatalf("route stopped: %d %s", resp.StatusCode, b)
		}
	}
	route()
	if _, e = p.Exec(ctx, "ALTER ROLE "+role+" NOLOGIN"); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1", role); e != nil {
		t.Fatal(e)
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		route()
		time.Sleep(100 * time.Millisecond)
	}
	var connections int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename=$1", role).Scan(&connections); e != nil || connections != 0 {
		t.Fatalf("edge DB outage not established: %d %v", connections, e)
	}
	if current := command(t, "docker", "exec", edgeName, "cat", "/tmp/gatebeam-nginx.pid"); current != master {
		t.Fatal("DB outage restarted Nginx")
	}
	t.Log("real PostgreSQL edge login disabled and connections terminated; existing route served with same child PID")
	if _, e = p.Exec(ctx, "ALTER ROLE "+role+" LOGIN"); e != nil {
		t.Fatal(e)
	}
	// Kill the actual parent/container and restart against the persistent journal.
	// Mid-switch interrupted journaling is covered independently by native recovery.
	command(t, "docker", "kill", "--signal", "KILL", edgeName)
	command(t, "docker", "start", edgeName)
	tlsPort = strings.TrimPrefix(command(t, "docker", "port", edgeName, "8443/tcp"), "127.0.0.1:")
	httpPort = strings.TrimPrefix(command(t, "docker", "port", edgeName, "8080/tcp"), "127.0.0.1:")
	await("/_gatebeam/ready")
	await("/readyz")
	route()
	t.Log("actual edge parent killed and restarted with persistent journal; current verified route restored")
	job, e := jobs.New(p).Enqueue(ctx, "deployment.rotate_logs", "native-rotation", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		var status string
		if e = p.QueryRow(ctx, "SELECT status FROM jobs WHERE id=$1", job).Scan(&status); e != nil {
			t.Fatal(e)
		}
		if status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rotation did not resume: %s", status)
		}
		time.Sleep(50 * time.Millisecond)
	}
	route()
	log := command(t, "docker", "exec", edgeName, "cat", "/state/logs/access.log")
	if strings.Contains(log, "must-not-log") || strings.Contains(log, "token=") {
		t.Fatal("query secret entered persisted access log")
	}
	if !strings.Contains(log, `"site_id":"`+siteID+`"`) || !strings.Contains(log, `"path_pattern":"/"`) {
		t.Fatal("persistent native log dimensions missing")
	}
	// Consume the actual native rename+USR1 outputs, including the unread
	// closed segment. Only owned fixture logs are copied to the local reader.
	localLogs := filepath.Join(t.TempDir(), "logs")
	command(t, "docker", "cp", edgeName+":/state/logs", localLogs)
	source, e := logfile.Open(localLogs)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	spoolDirectory := t.TempDir()
	writer, e := logspool.New(spoolDirectory)
	if e != nil {
		t.Fatal(e)
	}
	collector := ingest.New(postgres.NewRunner(p), logpg.New(), source, writer)
	segments, e := source.Discover(ctx)
	if e != nil {
		t.Fatal(e)
	}
	closed := 0
	var expected int64
	for _, segment := range segments {
		if segment.Closed {
			closed++
		}
		for step := 0; step < 8; step++ {
			batch, e := collector.Ingest(ctx, segment)
			if e != nil {
				t.Fatal(e)
			}
			if batch.End == 0 {
				break
			}
			for _, b := range batch.Buckets {
				expected += b.Count
			}
		}
	}
	if closed < 1 || expected < 2 {
		t.Fatalf("native unread closed segment missing: closed=%d records=%d", closed, expected)
	}
	var actual int64
	if e = p.QueryRow(ctx, "SELECT sum(requests) FROM observability_stats").Scan(&actual); e != nil || actual != expected {
		t.Fatal(actual, expected, e)
	}
	err := filepath.WalkDir(spoolDirectory, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !strings.HasSuffix(path, ".parquet") {
			return nil
		}
		rows, e := pq.ReadFile[logspool.Row](path)
		if e != nil {
			return e
		}
		for _, row := range rows {
			if row.SiteID == siteID && (row.PathPattern != "/" || row.Route != "default" || row.ConfigID == "") {
				t.Fatal("static route provenance missing", row)
			}
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		for _, secret := range []string{"must-not-log", "token=", "4111111111111111"} {
			if strings.Contains(string(data), secret) {
				t.Fatal("native secret entered Parquet")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func caPool(data []byte) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(data)
	return p
}
