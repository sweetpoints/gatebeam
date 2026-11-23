//go:build integration

package composition

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
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

const webNginxImage = "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"

// The browser fixture uses the production edge process, publication coordinator,
// PostgreSQL lease consumer and native Nginx. No HTTP route can fabricate an apply receipt.
func webEdge(t *testing.T, p *pgxpool.Pool, fixture map[string]any) {
	t.Helper()
	binary := os.Getenv("GATEBEAM_WEB_EDGE_BINARY")
	db := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if binary == "" || db == "" {
		t.Fatal("owned edge binary and PostgreSQL required for ingress acceptance")
	}
	command := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if e != nil {
			t.Fatalf("owned Docker fixture command %s: %v\n%s", args[0], e, b)
		}
		return strings.TrimSpace(string(b))
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	network := "gatebeam-web-" + suffix
	edge := network + "-edge"
	upstream := network + "-upstream"
	command("network", "create", "--internal", network)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", edge, upstream).Run()
		_ = exec.CommandContext(ctx, "docker", "network", "disconnect", network, db).Run()
		_ = exec.CommandContext(ctx, "docker", "network", "rm", network).Run()
	})
	prefix, e := netip.ParsePrefix(command("network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", network))
	if e != nil {
		t.Fatal(e)
	}
	// The network uses Docker's automatic IPAM pool. Docker26 rejects static
	// endpoint addresses unless the network has an explicitly configured subnet.
	// Discover the real assigned addresses rather than guessing allocation order.
	networkIP := func(container string) netip.Addr {
		address, err := netip.ParseAddr(command("inspect", "--format", fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", network), container))
		if err != nil || !address.Is4() || !prefix.Contains(address) {
			t.Fatal("owned fixture address is outside its Docker network", container, address, err)
		}
		return address
	}
	command("network", "connect", network, db)
	dbIP := networkIP(db)
	root := t.TempDir()
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(root, "state")
	files := filepath.Join(root, "fixture")
	if e = os.Mkdir(state, 0777); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(state, 0777); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(files, 0755); e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "browser management"}, DNSNames: []string{"management.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	dsn, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	dsn.Host = dbIP.String() + ":5432"
	query := dsn.Query()
	query.Set("search_path", p.Config().ConnConfig.RuntimeParams["search_path"])
	dsn.RawQuery = query.Encode()
	cfg := map[string]any{"environment": "development", "mode": "edge", "database_file": "/fixture/database", "edge_root": "/state", "management_domain": "management.test", "management_api_address": "10.254.254.254:8080", "management_certificate_file": "/fixture/management.pem", "management_key_file": "/fixture/management.key", "management_trust_file": "/fixture/management.pem"}
	if leafPath, ok := fixture["_leafIdentityPath"].(string); ok {
		leaf, e := os.ReadFile(leafPath)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(files, "leaf.agekey"), leaf, 0444); e != nil {
			t.Fatal(e)
		}
		cfg["certificate_identity_file"] = "/fixture/leaf.agekey"
		cfg["certificate_provider_recipient"] = fixture["_providerRecipient"]
		delete(fixture, "_leafIdentityPath")
		delete(fixture, "_providerRecipient")
	}
	config, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{"management.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "management.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), "database": []byte(dsn.String()), "edge.json": config} {
		if e = os.WriteFile(filepath.Join(files, name), data, 0444); e != nil {
			t.Fatal(e)
		}
	}
	command("run", "-d", "--name", upstream, "--network", network, "--memory", "128m", "--cpus", "0.5", "--pids-limit", "32", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", webNginxImage)
	upstreamIP := networkIP(upstream)
	command("create", "--name", edge, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "bridge", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--tmpfs", "/tmp:size=32m,mode=1777", "-p", "127.0.0.1::8080", "-p", "127.0.0.1::8443", "--mount", "type=bind,src="+files+",dst=/fixture,readonly", "--mount", "type=bind,src="+state+",dst=/state", "--mount", "type=bind,src="+binary+",dst=/gatebeam,readonly", "--entrypoint", "/gatebeam", webNginxImage, "--config", "/fixture/edge.json")
	command("network", "connect", network, edge)
	command("start", edge)
	if os.Getenv("GATEBEAM_WEB_SUITE") == "pki" {
		fixture["edgeTLSAddress"] = command("port", edge, "8443/tcp")
		fixture["edgeContainer"] = edge
		fixture["upstreamAddress"] = upstreamIP.String()
		fixture["upstreamNetwork"] = prefix.String()
		return
	}
	control := filepath.Join(root, "control")
	if e = os.Mkdir(control, 0777); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(control, 0777); e != nil {
		t.Fatal(e)
	}
	fixture["faultSignal"] = filepath.Join(control, "start")
	fixture["faultFile"] = filepath.Join(control, "fault")
	fixture["faultReady"] = filepath.Join(control, "ready")
	fixture["recoverSignal"] = filepath.Join(control, "recover")
	fixture["recoveredSignal"] = filepath.Join(control, "recovered")
	faultBinary := os.Getenv("GATEBEAM_WEB_FAULT_BINARY")
	faultName := network + "-fault"
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			if _, e := os.Stat(filepath.Join(control, "start")); e != nil {
				continue
			}
			started := time.Now()
			t.Log("preparing owned browser fault edge")
			command("stop", "-t", "2", edge)
			command("create", "--name", faultName, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "bridge", "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--tmpfs", "/tmp:size=32m,mode=1777", "-p", "127.0.0.1::8080", "--mount", "type=bind,src="+files+",dst=/fixture,readonly", "--mount", "type=bind,src="+state+",dst=/state", "--mount", "type=bind,src="+control+",dst=/control", "--mount", "type=bind,src="+faultBinary+",dst=/web-edge.test,readonly", "-e", "GATEBEAM_WEB_FAULT_EDGE=1", "--entrypoint", "/web-edge.test", webNginxImage, "-test.run", "^TestWebFaultEdge$", "-test.timeout", "80s")
			command("network", "connect", network, faultName)
			command("start", faultName)
			if e = os.WriteFile(filepath.Join(control, "url"), []byte("http://"+command("port", faultName, "8080/tcp")), 0666); e != nil {
				t.Error(e)
			}
			t.Logf("owned browser fault edge started; native baseline readiness still required, elapsed=%s", time.Since(started).Round(time.Millisecond))
			return
		}
	}()
	t.Cleanup(func() {
		close(done)
		wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", faultName).Run()
	})
	fixture["faultURLFile"] = filepath.Join(control, "url")
	fixture["edgeContainer"] = edge
	fixture["edgeURL"] = "http://" + command("port", edge, "8080/tcp")
	fixture["upstreamAddress"] = upstreamIP.String()
	fixture["upstreamNetwork"] = prefix.String()
}
