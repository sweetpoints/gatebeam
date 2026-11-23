//go:build integration

package acme_test

import (
	"context"
	"crypto/tls"
	"fmt"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	ingressapp "gatebeam/internal/modules/ingress/application"
	ingressdomain "gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/jobs"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The production worker owns DNS resolution and health scheduling. Changing an
// owned Docker DNS alias and the backend HTTP response exercises that path;
// this fixture never invokes health.Commit, Worker.Step, Compile or Reload.
func (e *publicEdge) periodicHealthDNS(worker string, leaf []byte) {
	t := e.t
	t.Helper()
	network := e.name + "-business"
	nativeCommand(t, "network", "create", "--internal", network)
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(nativeCommand(t, "logs", network+"-a"))
			t.Log(nativeCommand(t, "logs", worker))
			t.Log(nativeCommand(t, "exec", e.name, "getent", "hosts", "origin.owned.test"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		exec.CommandContext(ctx, "docker", "rm", "-f", network+"-a", network+"-b").Run()
		exec.CommandContext(ctx, "docker", "network", "disconnect", network, e.name).Run()
		exec.CommandContext(ctx, "docker", "network", "disconnect", network, worker).Run()
		exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	})
	subnet := nativeCommand(t, "network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", network)
	// The DNS replacement later preserves a specific endpoint address. Docker26
	// requires that address to belong to an explicitly configured network pool.
	nativeCommand(t, "network", "rm", network)
	nativeCommand(t, "network", "create", "--internal", "--subnet", subnet, network)
	nativeCommand(t, "network", "connect", network, e.name)
	nativeCommand(t, "network", "connect", network, worker)
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	start := func(suffix string, alias bool) {
		dir := filepath.Join(root, suffix)
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		cfg := "pid /tmp/nginx.pid; error_log stderr warn; events {} http { client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; access_log off; server { listen 8081; location = /health { return 200; } location / { return 200 'backend-" + suffix + "'; } } }"
		if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(cfg), 0644); err != nil {
			t.Fatal(err)
		}
		args := []string{"run", "-d", "--name", network + "-" + suffix, "--network", network, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "64m", "--cpus", ".5", "--pids-limit", "16", "--tmpfs", "/tmp:size=8m,mode=1777", "--mount", "type=bind,src=" + dir + ",dst=/backend,readonly", "--entrypoint", "nginx"}
		if alias {
			args = append(args, "--network-alias", "origin.owned.test")
		}
		args = append(args, "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "-c", "/backend/nginx.conf", "-g", "daemon off;")
		nativeCommand(t, args...)
	}
	start("a", true)
	start("b", false)
	if got := nativeCommand(t, "exec", e.name, "wget", "-qO-", "http://origin.owned.test:8081/"); got != "backend-a" {
		t.Fatal("owned backend readiness failed")
	}
	target, err := e.sites.SaveTarget(t.Context(), e.actor, ingressdomain.TargetGroup{Config: ingressdomain.TargetConfig{Name: "owned periodic target", Protocol: "http", HTTPHost: "origin.owned.test", Members: []ingressdomain.TargetMember{{Address: "origin.owned.test", Port: 8081, Weight: 1}}, AllowedNetworks: []string{subnet}, Health: ingressdomain.HealthPolicy{Enabled: true, Path: "/health", IntervalSeconds: 1, TimeoutSeconds: 1, HealthyThreshold: 1, UnhealthyThreshold: 1}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	site, err := e.sites.Site(t.Context(), e.actor, e.siteID)
	if err != nil {
		t.Fatal(err)
	}
	config := site.Draft.Clone()
	config.Maintenance = ingressdomain.MaintenancePolicy{}
	config.DefaultTarget = ingressdomain.TargetRef{ID: target.ID}
	revision, err := e.sites.SaveDraft(t.Context(), e.actor, ingressapp.Draft{SiteID: e.siteID, Config: config}, site.Revision)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := e.coordinator.Prepare(t.Context(), e.publisher, []string{e.siteID}, map[string]int64{"site:" + e.siteID: revision.Number, "target:" + target.ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.coordinator.Publish(t.Context(), e.publisher, candidate.ID); err != nil {
		t.Fatal(err)
	}
	e.releaseID = candidate.ID
	e.wantStatus = 200
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots, ServerName: "host.example", MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, e.address)
	}}}
	wait := func(status int, body, differentFrom string) string {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()
		lastStatus, lastBody, lastReceiptChecked, lastReceipt := 0, "", false, false
		for {
			r, err := client.Get("https://host.example/")
			if err == nil {
				b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
				r.Body.Close()
				lastStatus, lastBody = r.StatusCode, string(b)
				lastReceiptChecked, lastReceipt = false, false
				if r.StatusCode == status && (body == "" || string(b) == body) {
					lastReceiptChecked = true
					lastReceipt = e.receiptMatches(ctx, leaf)
					if lastReceipt && (differentFrom == "" || e.receiptVersion != differentFrom) {
						return e.receiptVersion
					}
				}
			}
			if ctx.Err() != nil {
				e.diagnose()
				t.Fatalf("periodic native route not settled: expected_status=%d expected_body=%q observed_status=%d observed_body=%q receipt_checked=%t receipt_matched=%t expected_release=%s different_from=%s last_error=%v", status, body, lastStatus, lastBody, lastReceiptChecked, lastReceipt, e.releaseID, differentFrom, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	wait(200, "backend-a", "")
	// Keep the owned source valid throughout the unrelated lease/health/DNS
	// faults. The worker has only internal networks after initial issuance.
	// Arm a fresh short expiry through the real dirty/generation path just
	// before the outage, rather than letting this preparation consume its TTL.
	initialExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	gateway := nativeCommand(t, "inspect", "--format", "{{(index .NetworkSettings.Networks \"bridge\").Gateway}}", e.name)
	runtime := deploymentpg.NewRuntime(e.db, jobs.New(e.db), nil)
	if err := runtime.SaveCloudflare(t.Context(), edge.CloudflareSet{Generation: "owned-stable", ValidUntil: initialExpiry, Networks: []netip.Prefix{netip.MustParsePrefix(gateway + "/32")}}); err != nil {
		t.Fatal(err)
	}
	cfConfig := config.Clone()
	cfConfig.Domains = []string{"cf.example"}
	cfConfig.Cloudflare = ingressdomain.CFPolicy{Mode: "proxied"}
	cfSite, err := e.sites.CreateSite(t.Context(), e.actor, ingressapp.CreateSite{Name: "owned CF site", Config: cfConfig})
	if err != nil {
		t.Fatal(err)
	}
	cfCandidate, err := e.coordinator.Prepare(t.Context(), e.publisher, []string{cfSite.ID}, map[string]int64{"site:" + cfSite.ID: 1, "target:" + target.ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.coordinator.Publish(t.Context(), e.publisher, cfCandidate.ID); err != nil {
		t.Fatal(err)
	}
	e.releaseID = cfCandidate.ID
	wait(200, "backend-a", "")
	cfClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots, ServerName: "cf.example", MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, e.address)
	}}}
	cfStatus := func() int {
		t.Helper()
		req, err := http.NewRequest("GET", "https://cf.example/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("CF-Connecting-IP", "203.0.113.8")
		r, err := cfClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if status := cfStatus(); status != 200 {
		t.Fatal("valid owned CF range denied", status)
	}
	// Block the actual authorization read before Prepare's lease fence. A row
	// lock on immutable deployment_candidates does not block its MVCC SELECT.
	// Observe the edge waiting on identity_watermark, then expire its lease;
	// the stale attempt must perform no native effect.
	leasedCandidate, err := e.coordinator.Prepare(t.Context(), e.publisher, []string{e.siteID}, map[string]int64{"site:" + e.siteID: revision.Number, "target:" + target.ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	nativeCommand(t, "pause", e.name)
	paused := true
	defer func() {
		if paused {
			nativeCommand(t, "unpause", e.name)
		}
	}()
	if _, err = e.coordinator.Publish(t.Context(), e.publisher, leasedCandidate.ID); err != nil {
		t.Fatal(err)
	}
	blocked, err := e.db.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if _, err = blocked.Exec(t.Context(), "SELECT id FROM identity_watermark WHERE id=1 FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	nativeCommand(t, "unpause", e.name)
	paused = false
	deadline := time.Now().Add(4 * time.Second)
	for {
		var state string
		err = e.db.QueryRow(t.Context(), "SELECT status FROM jobs WHERE kind='deployment.apply' AND key=$1", leasedCandidate.ID).Scan(&state)
		var waiting bool
		waitErr := e.db.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%identity_watermark%')`, e.edgeRole).Scan(&waiting)
		if err == nil && state == "running" && waitErr == nil && waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual edge never blocked on the authorization fence", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	beforeLease := nativeCommand(t, "exec", e.name, "wget", "-qO-", "http://127.0.0.1:9090/version")
	if strings.HasPrefix(beforeLease, leasedCandidate.ID+"/") {
		t.Fatal("blocked candidate already reached native process", beforeLease)
	}
	if _, err = e.db.Exec(t.Context(), "UPDATE jobs SET deadline=clock_timestamp()-interval '1 second' WHERE kind='deployment.apply' AND key=$1", leasedCandidate.ID); err != nil {
		t.Fatal(err)
	}
	if err = blocked.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.releaseID = leasedCandidate.ID
	wait(200, "backend-a", "")
	var attempts int
	if err = e.db.QueryRow(t.Context(), "SELECT attempt FROM jobs WHERE kind='deployment.apply' AND key=$1", leasedCandidate.ID).Scan(&attempts); err != nil || attempts != 2 {
		t.Fatal("expired actual edge lease was not reclaimed exactly once", attempts, err)
	}
	if afterLease := nativeCommand(t, "exec", e.name, "wget", "-qO-", "http://127.0.0.1:9090/version"); beforeLease == afterLease {
		t.Fatal("fresh reclaimed candidate did not activate", "before", beforeLease, "after", afterLease, "expected release", leasedCandidate.ID)
	}
	t.Log("actual edge lease expired while blocked before preparation fence; no stale native effect; second claimed attempt alone reached final exact receipt")

	var initial string
	if err := e.db.QueryRow(t.Context(), "SELECT version FROM deployment_runtime WHERE id").Scan(&initial); err != nil {
		t.Fatal(err)
	}
	// Isolated backend failure drives periodic health -> dirty fixed job -> edge.
	backendConfig := filepath.Join(root, "a", "nginx.conf")
	raw, err := os.ReadFile(backendConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(backendConfig, []byte(strings.Replace(string(raw), "location = /health { return 200; }", "location = /health { return 503; }", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	nativeCommand(t, "exec", network+"-a", "nginx", "-c", "/backend/nginx.conf", "-s", "reload")
	wait(503, "", "")
	// A different address takes the same DNS name. Revoke the publishing session
	// before recovery: derived current-security work must continue without it.
	replacementIP := nativeCommand(t, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", network+"-b")
	nativeCommand(t, "network", "disconnect", network, network+"-a")
	nativeCommand(t, "network", "disconnect", network, network+"-b")
	nativeCommand(t, "network", "connect", "--ip", replacementIP, "--alias", "origin.owned.test", network, network+"-b")
	e.revokePublisher()
	wait(200, "backend-b", "")
	e.wait(leaf)
	if _, err := e.coordinator.Publish(t.Context(), e.publisher, candidate.ID); err == nil {
		t.Fatal("expired publisher replay accepted")
	}
	var final string
	var jobs int
	if err := e.db.QueryRow(t.Context(), "SELECT version FROM deployment_runtime WHERE id").Scan(&final); err != nil {
		t.Fatal(err)
	}
	if err := e.db.QueryRow(t.Context(), "SELECT count(*) FROM jobs WHERE kind='deployment.generation' AND status='completed'").Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if final == initial || jobs < 2 {
		t.Fatal("periodic dirty jobs/generations missing", jobs)
	}
	// The separately mounted worker/provider and API/auth identities must not be
	// readable from edge, and neither management process receives a query socket.
	for _, v := range []struct {
		name  string
		paths []string
	}{{e.name, []string{"/worker/provider.agekey", "/fixture/worker/provider.agekey", "/api/identity.agekey", "/run/query/query.sock", "/run/gatebeam/issuer.age"}}, {worker, []string{"/fixture/materials.agekey", "/api/identity.agekey", "/run/gatebeam/issuer.age"}}, {e.name + "-api", []string{"/fixture/materials.agekey", "/worker/provider.agekey", "/run/query/query.sock", "/run/gatebeam/issuer.age"}}} {
		for _, path := range v.paths {
			out := nativeCommand(t, "exec", v.name, "sh", "-c", fmt.Sprintf("if test -r '%s'; then exit 1; fi; printf denied", path))
			if strings.TrimSpace(out) != "denied" {
				t.Fatal("negative mount capability failed")
			}
		}
	}

	previousVersion := nativeCommand(t, "exec", e.name, "wget", "-qO-", "http://127.0.0.1:9090/version")
	window := 18 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		window = 30 * time.Second
	}
	expiry := time.Now().Add(window).Truncate(time.Second)
	if err := runtime.SaveCloudflare(t.Context(), edge.CloudflareSet{Generation: "owned-outage-expiry", ValidUntil: expiry, Networks: []netip.Prefix{netip.MustParsePrefix(gateway + "/32")}}); err != nil {
		t.Fatal(err)
	}
	// receiptMatches proves the exact current DB/journal/native version. A
	// different version is required so the old hour-long source cannot pass.
	nativeVersion := wait(200, "backend-b", previousVersion)
	nginxPID := nativeCommand(t, "exec", e.name, "cat", "/tmp/gatebeam-nginx.pid")
	nativeCommand(t, "stop", "-t", "2", worker)
	if _, err := e.db.Exec(t.Context(), "ALTER ROLE "+pgx.Identifier{e.edgeRole}.Sanitize()+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(t.Context(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1", e.edgeRole); err != nil {
		t.Fatal(err)
	}
	// Establish the same-run causal precondition after both actual faults:
	// fresh TLS access must still work, and must finish before input expiry.
	if status := cfStatus(); status != 200 {
		t.Fatal("owned CF source was not valid after the control outage began", status)
	}
	observed := time.Now()
	if !observed.Before(expiry) {
		t.Fatal("owned CF source expired before the outage precondition was observed")
	}
	t.Logf("CF outage precondition: worker stopped, edge DB login disabled and sessions terminated, status=200 remaining=%s input_window=%s", expiry.Sub(observed), window)
	if until := time.Until(expiry.Add(200 * time.Millisecond)); until > 0 {
		time.Sleep(until)
	}
	if status := cfStatus(); status != 403 {
		t.Fatal("native CF TTL survived DB/worker outage", status)
	}
	r, err := client.Get("https://host.example/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("CF expiry stopped unaffected business site")
	}
	if nativeVersion != nativeCommand(t, "exec", e.name, "wget", "-qO-", "http://127.0.0.1:9090/version") || nginxPID != nativeCommand(t, "exec", e.name, "cat", "/tmp/gatebeam-nginx.pid") {
		t.Fatal("outage TTL depended on reload/restart")
	}
	t.Log("native per-site $msec TTL crossed from valid 200 to expired 403 during actual edge-DB login outage + stopped worker; unaffected business site 200, unchanged native version and Nginx master PID")
	t.Logf("separate API/worker/edge: periodic healthy→503→DNS replacement recovery; completed generation jobs=%d, expired publisher rejected, exact current receipt/TLS/binding and unrelated draft preserved", jobs)
}
