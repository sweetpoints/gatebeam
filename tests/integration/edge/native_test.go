package edge_test

import (
	"bufio"
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
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const image = "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) authority {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	c, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return authority{c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
func (c authority) leaf(t *testing.T, name string, client bool) ([]byte, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{name}, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &k.PublicKey, c.key)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}
func (c authority) crl(t *testing.T) []byte {
	t.Helper()
	der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, c.cert, c.key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
func command(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%v: %v\n%s", args, e, out)
	}
	return strings.TrimSpace(string(out))
}

type fixture struct {
	name, root, port, ip string
	snapshot             app.Snapshot
	state                edge.RuntimeState
	pool                 *x509.CertPool
	ca                   authority
	clients              map[string]tls.Certificate
}

func setup(t *testing.T) *fixture { return setupLifetime(t, 180) }

func setupLifetime(t *testing.T, seconds int) *fixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	project := filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
	root := t.TempDir()
	binary := filepath.Join(root, "backend")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", binary, "./tests/fixtures/edge/backend")
	cmd.Dir = project
	arch := os.Getenv("GATEBEAM_TARGET_ARCH")
	if arch == "" {
		arch = command(t, "docker", "image", "inspect", image, "--format", "{{.Architecture}}")
	}
	if arch != "amd64" && arch != "arm64" {
		t.Fatal("unsupported container fixture architecture")
	}
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build fixture: %v %s", e, out)
	}
	f := &fixture{root: root, name: fmt.Sprintf("gatebeam-i3-%d", time.Now().UnixNano()), clients: map[string]tls.Certificate{}}
	command(t, "docker", "run", "-d", "--name", f.name, "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-p", "127.0.0.1::8443", "-v", root+":/fixture:ro", image, "sh", "-c", fmt.Sprintf("sleep %d", seconds))
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(command(t, "docker", "logs", f.name))
			t.Log(string(mustRead(filepath.Join(f.root, "nginx.conf"))))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		exec.CommandContext(ctx, "docker", "rm", "-f", f.name).Run()
	})
	f.ip = command(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", f.name)
	f.port = strings.TrimPrefix(command(t, "docker", "port", f.name, "8443/tcp"), "127.0.0.1:")
	ca := newCA(t, "fixture server CA")
	f.ca = ca
	f.pool = x509.NewCertPool()
	f.pool.AppendCertsFromPEM(ca.pem)
	for _, n := range []string{"a", "b"} {
		cert, key := ca.leaf(t, n+".internal.test", false)
		os.WriteFile(filepath.Join(root, n+".pem"), cert, 0600)
		os.WriteFile(filepath.Join(root, n+".key"), key, 0600)
	}
	f.state = edge.RuntimeState{Generation: "fixture-1", Now: time.Now(), Materials: map[string]edge.Material{"trust": {Revision: 1, TrustPEM: ca.pem, CRLPEM: ca.crl(t)}}}
	f.snapshot = app.Snapshot{Version: "fixture-v1", Targets: []app.Target{{ID: "target", Revision: 1, Config: app.TargetConfig{Protocol: "https", TLSNameMode: "member", Trust: &app.MaterialRef{ID: "trust", Revision: 1}, AllowedNetworks: []string{f.ip + "/32"}, Members: []app.TargetMember{{Address: f.ip, Port: 9443, Weight: 1, TLSName: "a.internal.test"}, {Address: f.ip, Port: 9444, Weight: 3, TLSName: "b.internal.test"}}}}}}
	command(t, "docker", "exec", "-d", f.name, "/fixture/backend", "/fixture")
	return f
}
func (f *fixture) addSite(t *testing.T, name string) *app.SiteConfig {
	cert, key := f.ca.leaf(t, name, false)
	f.state.Materials[name] = edge.Material{Revision: 1, CertificatePEM: cert, KeyPEM: key}
	f.snapshot.Sites = append(f.snapshot.Sites, app.Site{ID: name, Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{name}, DefaultTarget: app.TargetRef{ID: "target"}, EntryCertificate: &app.MaterialRef{ID: name, Revision: 1}, Cloudflare: app.CFPolicy{Mode: "off"}, Connection: app.ConnectionPolicy{WebSocket: true, SSE: true}}})
	return &f.snapshot.Sites[len(f.snapshot.Sites)-1].Config
}
func (f *fixture) writeConfiguration(t *testing.T) {
	t.Helper()
	a, e := (nginx.Compiler{}).Compile(f.snapshot, f.state)
	if e != nil {
		t.Fatal(e)
	}
	for path, data := range a.Files {
		full := filepath.Join(f.root, path)
		os.MkdirAll(filepath.Dir(full), 0700)
		if e := os.WriteFile(full, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func (f *fixture) start(t *testing.T) {
	f.startBeforeLaunch(t, nil)
}
func (f *fixture) startBeforeLaunch(t *testing.T, arm func()) {
	t.Helper()
	f.writeConfiguration(t)
	command(t, "docker", "exec", f.name, "nginx", "-t", "-p", "/fixture/", "-c", "nginx.conf")
	if arm != nil {
		// Short-lived inputs start after expensive fixture preparation. Nginx
		// still parses the resulting configuration itself during its startup.
		arm()
		f.writeConfiguration(t)
	}
	// Start the real daemon and observe readiness in the same Docker exec.
	// An additional client process startup must not consume the expiry window.
	command(t, "docker", "exec", f.name, "sh", "-c", "nginx -p /fixture/ -c nginx.conf && for i in $(seq 1 30); do wget -qO- http://127.0.0.1:9090/version && exit 0; sleep 0.1; done; exit 1")
}
func (f *fixture) client(name string, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: f.pool, ServerName: name, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, "127.0.0.1:"+f.port)
	}, DisableKeepAlives: true}}
}
func request(t *testing.T, c *http.Client, host, path, body string, headers map[string]string) (int, map[string]string) {
	t.Helper()
	r, e := http.NewRequest("POST", "https://"+host+path, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, e := c.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if e != nil {
		t.Fatal(e)
	}
	data := map[string]string{}
	if resp.StatusCode == 200 {
		if e = json.Unmarshal(b, &data); e != nil {
			t.Fatalf("bad backend %q %v", b, e)
		}
	}
	return resp.StatusCode, data
}
func TestPerMemberSNIUsesSelectedEndpoint(t *testing.T) {
	f := setup(t)
	f.addSite(t, "business.test")
	f.start(t)
	client := f.client("business.test", nil)
	counts := map[string]int{}
	for i := 0; i < 16; i++ {
		status, d := request(t, client, "BuSiNeSs.TeSt:443", "/raw%2Fpath?x=1&x=2", "payload", nil)
		if status != 200 || d["host"] != "BuSiNeSs.TeSt:443" || d["uri"] != "/raw%2Fpath?x=1&x=2" || d["method"] != "POST" || d["body"] != "payload" {
			t.Fatalf("HTTP/SNI contract status=%d data=%v", status, d)
		}
		counts[d["sni"]]++
	}
	if counts["a.internal.test"] != 4 || counts["b.internal.test"] != 12 {
		t.Fatalf("weighted SNI %v", counts)
	}
}
func TestHTTPContracts(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "http.test")
	c.Routes = []app.Route{{Match: "prefix", Path: "/strip/", StripPrefix: true, Target: app.TargetRef{ID: "target"}}}
	f.start(t)
	client := f.client("http.test", nil)
	status, d := request(t, client, "http.test", "/strip/ok?a=%2F", "body", map[string]string{"X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "5.6.7.8", "Forwarded": "for=9.8.7.6"})
	if status != 200 || d["uri"] != "/ok?a=%2F" || d["body"] != "body" || d["xff"] == "1.2.3.4" || d["xff"] == "5.6.7.8" || d["cf"] != "" || d["forwarded"] != "" {
		t.Fatalf("preservation/trust %d %v", status, d)
	}
	cfg := &tls.Config{RootCAs: f.pool, ServerName: "http.test"}
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:"+f.port, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: http.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	reader := bufio.NewReader(conn)
	resp, e := http.ReadResponse(reader, nil)
	if e != nil || resp.StatusCode != 101 {
		t.Fatalf("WS handshake %v %v", resp, e)
	}
	conn.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'o' ^ 1, 'k' ^ 2})
	frame := make([]byte, 4)
	if _, e = io.ReadFull(reader, frame); e != nil || !bytes.Equal(frame, []byte{0x81, 2, 'o', 'k'}) {
		t.Fatalf("WS frame %v %v", frame, e)
	}
	probeSSE := func(path string) time.Duration {
		t.Helper()
		response, e := client.Get("https://http.test" + path)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
			t.Fatal("SSE response contract", response.StatusCode, response.Header)
		}
		stream := bufio.NewReader(response.Body)
		idLine, e := stream.ReadString('\n')
		if e != nil || !strings.HasPrefix(idLine, "id: ") {
			t.Fatalf("SSE emission id %q %v", idLine, e)
		}
		emitted, e := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(idLine, "id: ")), 10, 64)
		if e != nil {
			t.Fatal("invalid owned SSE emission timestamp", e)
		}
		line, e := stream.ReadString('\n')
		latency := time.Since(time.Unix(0, emitted))
		if e != nil || line != "data: first\n" || latency < 0 {
			t.Fatalf("SSE first event %q latency=%s %v", line, latency, e)
		}
		t.Logf("owned SSE %s emission-to-receive latency=%s", path, latency)
		return latency
	}
	if latency := probeSSE("/sse"); latency > 300*time.Millisecond {
		t.Fatalf("SSE buffering latency=%s", latency)
	}
	if latency := probeSSE("/sse-buffered"); latency <= 300*time.Millisecond {
		t.Fatalf("SSE probe accepted deliberately buffered headers/body latency=%s", latency)
	}
}
func TestNativeCrossVhostMTLSAndUnknownSNI(t *testing.T) {
	f := setup(t)
	for _, name := range []string{"one.test", "two.test"} {
		c := f.addSite(t, name)
		ca := newCA(t, name+" client CA")
		cert, key := ca.leaf(t, name+" client", true)
		pair, _ := tls.X509KeyPair(cert, key)
		f.clients[name] = pair
		f.state.Materials[name+"trust"] = edge.Material{Revision: 1, TrustPEM: ca.pem, CRLPEM: ca.crl(t)}
		c.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: name + "trust", Revision: 1}, Depth: 2, Revocation: "crl"}
	}
	f.start(t)
	pair := f.clients["one.test"]
	client := f.client("one.test", &pair)
	status, _ := request(t, client, "ONE.TEST:443", "/", "", nil)
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = request(t, client, "two.test", "/", "", nil)
	if status == 200 {
		t.Fatal("cross-vhost client CA bypass")
	}
	status, _ = request(t, f.client("one.test", nil), "one.test", "/", "", nil)
	if status == 200 {
		t.Fatal("missing client cert accepted")
	}
	if _, e := f.client("unknown.test", nil).Get("https://unknown.test/"); e == nil {
		t.Fatal("unknown SNI accepted")
	}
	if conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:"+f.port, &tls.Config{RootCAs: f.pool}); e == nil {
		conn.Close()
		t.Fatal("no-SNI accepted")
	}
	if _, e := client.Get("https://unknown-host.test/"); e == nil {
		t.Fatal("unknown Host accepted under known SNI")
	}

}

// burstStatuses completes TLS preparation before releasing HTTP requests
// together. The rate window therefore measures request arrival, not repeated
// connection setup or TLS handshake latency on a software CPU.
func (f *fixture) burstStatuses(t *testing.T, host string, paths []string) []int {
	t.Helper()
	connections := make([]*tls.Conn, len(paths))
	requests := make([]*http.Request, len(paths))
	for i, path := range paths {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", "127.0.0.1:"+f.port, &tls.Config{RootCAs: f.pool, ServerName: host, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		connections[i] = conn
		defer conn.Close()
		requests[i], err = http.NewRequest(http.MethodPost, "https://"+host+path, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		status int
		err    error
	}
	ready := make(chan struct{})
	results := make(chan result, len(paths))
	for i, conn := range connections {
		go func(conn *tls.Conn, req *http.Request) {
			<-ready
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				results <- result{err: err}
				return
			}
			if err := req.Write(conn); err != nil {
				results <- result{err: err}
				return
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				results <- result{err: err}
				return
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			results <- result{status: response.StatusCode, err: err}
		}(conn, requests[i])
	}
	close(ready)
	statuses := make([]int, 0, len(paths))
	for range paths {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		statuses = append(statuses, r.status)
	}
	return statuses
}

func TestNativeRateAndCloudflareTrust(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "rate.test")
	c.Rate = app.RatePolicy{RequestsPerSecond: 1, Burst: 2}
	c.Routes = []app.Route{{Match: "prefix", Path: "/cap/", Target: app.TargetRef{ID: "target"}, Rate: &app.RatePolicy{RequestsPerSecond: 1}}}
	c = f.addSite(t, "cf.test")
	c.Cloudflare = app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{"10.254.254.0/24"}}
	c = f.addSite(t, "trusted-cf.test")
	c.Cloudflare = app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{"0.0.0.0/0"}}
	f.addSite(t, "ordinary.test")
	f.state.Cloudflare = edge.CloudflareSet{ValidUntil: time.Now().Add(time.Hour), Generation: "official-fixture", Networks: []netip.Prefix{netip.MustParsePrefix("10.254.254.0/24"), netip.MustParsePrefix(command(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", f.name) + "/32")}}
	f.start(t)
	pathStatuses := f.burstStatuses(t, "rate.test", []string{"/cap/one?secret=must-not-retain-i4", "/cap/two?secret=must-not-retain-i4"})
	accepted, limited := 0, 0
	for _, status := range pathStatuses {
		if status == 200 {
			accepted++
		}
		if status == 429 {
			limited++
		}
	}
	if accepted != 1 || limited != 1 {
		t.Fatalf("path cap %v", pathStatuses)
	}
	hits := 0
	for _, status := range f.burstStatuses(t, "rate.test", []string{"/x", "/y", "/z", "/q"}) {
		if status == 429 {
			hits++
		}
	}
	if hits == 0 {
		t.Fatal("path cap bypassed site cap")
	}
	s, _ := request(t, f.client("cf.test", nil), "cf.test", "/", "", map[string]string{"CF-Connecting-IP": "10.254.254.1", "X-Forwarded-For": "10.254.254.1"})
	if s != 403 {
		t.Fatalf("draft broadened CF trust: %d", s)
	}
	s, data := request(t, f.client("trusted-cf.test", nil), "trusted-cf.test", "/", "", map[string]string{"CF-Connecting-IP": "203.0.113.7", "X-Forwarded-For": "1.2.3.4"})
	if s != 200 || data["xff"] != "203.0.113.7" {
		t.Fatalf("trusted CF peer %d %v", s, data)
	}
	request(t, f.client("ordinary.test", nil), "ordinary.test", "/ordinary429", "", nil)
	logs := command(t, "docker", "exec", f.name, "cat", "/tmp/access.log")
	rejected, ordinary := false, false
	for _, line := range strings.Split(logs, "\n") {
		var entry struct {
			Status   int    `json:"status"`
			Rate     string `json:"rate_req"`
			Upstream string `json:"upstream_outcome"`
		}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if entry.Status == 429 && entry.Rate == "REJECTED" && entry.Upstream == "none" {
			rejected = true
		}
		if entry.Status == 429 && entry.Rate == "" && entry.Upstream == "client_error" {
			ordinary = true
		}
	}
	if !rejected || !ordinary {
		t.Fatalf("missing rate-hit metadata %s", logs)
	}
	retainedErrors := command(t, "docker", "exec", f.name, "cat", "/tmp/error.log")
	if strings.Contains(logs, "must-not-retain-i4") || strings.Contains(retainedErrors, "must-not-retain-i4") {
		t.Fatal("request query sentinel leaked to retained logs despite safe structured status")
	}

}

func mustRead(p string) []byte { b, _ := os.ReadFile(p); return b }
func TestNativeTLSFailClosedAndLifecycle(t *testing.T) {
	f := setup(t)
	f.addSite(t, "bad-tls.test")
	f.snapshot.Targets[0].Config.Members[0].TLSName = "wrong.internal.test"
	f.snapshot.Targets[0].Config.Members[1].Weight = 1
	c := f.addSite(t, "maintenance.test")
	c.Maintenance = app.MaintenancePolicy{Enabled: true, Status: 503, Message: "Scheduled \"maintenance\" $host; {ok}"}
	c = f.addSite(t, "disabled.test")
	c.Enabled = false
	c = f.addSite(t, "upload.test")
	c.Connection.MaxBodyBytes = 4
	c = f.addSite(t, "denied.test")
	c.Access.Allow = []string{"203.0.113.0/24"}
	f.start(t)
	for _, tc := range []struct {
		name, body string
		want       int
	}{{"bad-tls.test", "", 502}, {"maintenance.test", "", 503}, {"upload.test", "12345", 413}, {"denied.test", "", 403}} {
		s, _ := request(t, f.client(tc.name, nil), tc.name, "/", tc.body, nil)
		if s != tc.want {
			t.Fatalf("%s got%d want%d", tc.name, s, tc.want)
		}
	}
	response, e := f.client("maintenance.test", nil).Get("https://maintenance.test/")
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != `Scheduled "maintenance" $host; {ok}` {
		t.Fatalf("maintenance text injection/alteration: %q", body)
	}
	if _, e := f.client("disabled.test", nil).Get("https://disabled.test/"); e == nil {
		t.Fatal("disabled TLS site still exists")
	}
}
func TestNativeAdditionalPathConnectionCap(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "connections.test")
	c.Rate = app.RatePolicy{Connections: 2}
	c.Routes = []app.Route{{Match: "prefix", Path: "/sse", Target: app.TargetRef{ID: "target"}, Rate: &app.RatePolicy{Connections: 1}}}
	f.start(t)
	client := f.client("connections.test", nil)
	response, e := client.Get("https://connections.test/sse")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if _, e = reader.ReadString('\n'); e != nil {
		t.Fatal(e)
	}
	s, _ := request(t, client, "connections.test", "/sse", "", nil)
	if s != 429 {
		t.Fatalf("path connection cap got%d", s)
	}
	logs := command(t, "docker", "exec", f.name, "cat", "/tmp/access.log")
	if !strings.Contains(logs, `"rate_conn":"REJECTED"`) {
		t.Fatal("missing connection cap metadata", logs)
	}
}

func TestNativeApprovedOriginPullTrust(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "aop.test")
	ca := newCA(t, "owned approved AOP fixture CA")
	cert, key := ca.leaf(t, "fixture-origin-pull", true)
	pair, _ := tls.X509KeyPair(cert, key)
	c.Cloudflare = app.CFPolicy{Mode: "proxied", RequireOriginPull: true}
	c.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "aop-trust", Revision: 1}, Depth: 2, Revocation: "crl"}
	f.state.Materials["aop-trust"] = edge.Material{Revision: 1, TrustPEM: ca.pem, CRLPEM: ca.crl(t)}
	f.state.Cloudflare = edge.CloudflareSet{ValidUntil: time.Now().Add(time.Hour), Generation: "official-fixture", Networks: []netip.Prefix{netip.MustParsePrefix(command(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", f.name) + "/32")}}
	if _, e := (nginx.Compiler{}).Compile(f.snapshot, f.state); e == nil {
		t.Fatal("ordinary client CA mislabeled approved origin pull trust")
	}
	material := f.state.Materials["aop-trust"]
	material.OriginPullAuthorized = true
	f.state.Materials["aop-trust"] = material
	f.start(t)
	status, d := request(t, f.client("aop.test", &pair), "aop.test", "/", "", map[string]string{"CF-Connecting-IP": "203.0.113.8"})
	if status != 200 || d["xff"] != "203.0.113.8" {
		t.Fatalf("native approved AOP %d %v", status, d)
	}
}
func TestNativeDeniedPathCannotBeOverriddenByExactRoute(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "paths.test")
	c.Access.DenyPaths = []string{"/private"}
	c.Routes = []app.Route{{Match: "exact", Path: "/private/login", Target: app.TargetRef{ID: "target"}}}
	f.start(t)
	s, _ := request(t, f.client("paths.test", nil), "paths.test", "/private/login", "", nil)
	if s != 403 {
		t.Fatalf("exact route bypassed denied prefix: %d", s)
	}
}
func TestNativeDraftCannotBroadenOfficialCloudflarePeers(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "untrusted-cf.test")
	c.Cloudflare = app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{"0.0.0.0/0"}}
	f.state.Cloudflare = edge.CloudflareSet{ValidUntil: time.Now().Add(time.Hour), Generation: "official-fixture", Networks: []netip.Prefix{netip.MustParsePrefix("10.254.254.0/24")}}
	f.start(t)
	s, _ := request(t, f.client("untrusted-cf.test", nil), "untrusted-cf.test", "/", "", map[string]string{"CF-Connecting-IP": "10.254.254.1", "X-Forwarded-For": "10.254.254.1"})
	if s != 403 {
		t.Fatalf("draft broadened official peer set: %d", s)
	}
}
