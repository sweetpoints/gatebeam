//go:build integration

package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	management "gatebeam/internal/modules/pki/application"
	app "gatebeam/internal/modules/pki/application/acme"
	"gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/modules/pki/infrastructure/http01"
	josecrypto "gatebeam/internal/modules/pki/infrastructure/jose"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam/internal/modules/pki/transport/acme"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	pkifixture "gatebeam/tests/fixtures/pki"
	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/http/webroot"
	"github.com/go-acme/lego/v5/registration"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nginxImage = "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"

type fixtureConfig struct {
	DSN, Network string
	NativeStatus bool
}

// The subprocess uses the same production services and real restricted CA login.
// A short signer lifetime makes automatic renewal observable in bounded wall time.
func TestMain(m *testing.M) {
	if os.Getenv("GATEBEAM_CLOCK_SAMPLE") == "1" {
		fmt.Println(time.Now().UTC().Format(time.RFC3339Nano))
		return
	}
	if path := os.Getenv("GATEBEAM_P4_STATUS_FIXTURE"); path != "" {
		if e := serveStatusProcess(path); e != nil {
			fmt.Fprintln(os.Stderr, "status fixture failed")
			os.Exit(1)
		}
		return
	}
	if os.Getenv("GATEBEAM_P3_CA_FIXTURE") == "1" {
		if e := serveFixture(); e != nil {
			fmt.Fprintln(os.Stderr, "CA fixture failed:", e)
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}
func serveFixture() error {
	b, e := os.ReadFile("/lab/fixture.json")
	if e != nil {
		return e
	}
	var cfg fixtureConfig
	if e = json.Unmarshal(b, &cfg); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, e := pgxpool.New(ctx, cfg.DSN)
	if e != nil {
		return e
	}
	defer db.Close()
	if e = repo.CheckCARole(ctx, db); e != nil {
		return e
	}
	i, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: "/lab/online/issuer.pem", RootFile: "/lab/online/root.pem", SignerFile: "/lab/online/issuer.age", IdentityFile: "/lab/online/identity.agekey"})
	if e != nil {
		return e
	}
	sec, e := secrets.New("/lab/online/identity.agekey")
	if e != nil {
		return e
	}
	denied := []string{}
	for _, host := range []string{"ca.internal.test", "pki-db"} {
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return e
		}
		for _, ip := range ips {
			n, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				return fmt.Errorf("fixture control address invalid")
			}
			n = n.Unmap()
			denied = append(denied, netip.PrefixFrom(n, n.BitLen()).String())
		}
	}
	if cfg.NativeStatus {
		return serveClientIdentityCA(ctx, db, i, cfg.Network, denied)
	}
	v, e := http01.New([]string{cfg.Network}, denied)
	if e != nil {
		return e
	}
	tx := postgres.NewRunner(db)
	r := repo.New()
	if e = management.NewRegistry(tx, r).Register(ctx, i.Metadata(), i.Certificate.Raw); e != nil {
		return e
	}
	orders := app.NewOrders(tx, r, pkicrypto.Random{}, v, pkicrypto.OrderSigner{Issuer: i, Lifetime: 45 * time.Second}, nil)
	protocol, e := transport.NewProtocol("https://ca.internal.test:8443", app.New(tx, r, pkicrypto.Random{}, sec, nil), app.NewNonces(tx, r, pkicrypto.Random{}, nil), josecrypto.Crypto{}, orders)
	if e != nil {
		return e
	}
	server := http.Server{Addr: ":8443", Handler: protocol, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, TLSConfig: transport.TLSConfig()}
	return server.ListenAndServeTLS("/lab/transport.pem", "/lab/transport-key.pem")
}

type security struct{ tx transaction.Runner }

func (s security) Within(ctx context.Context, _ management.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}
func command(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := containerCommandContext(context.Background(), args...)
	defer cancel()
	started := time.Now()
	c := exec.CommandContext(ctx, "docker", args...)
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("docker %s elapsed_ms=%d deadline_expired=%t: %v: %s", args[0], time.Since(started).Milliseconds(), ctx.Err() == context.DeadlineExceeded, e, b)
	}
	return strings.TrimSpace(string(b))
}

// Starting an owned container is fixture preparation, not a TLS, renewal or
// revocation assertion. Keep executable probes and all other commands bounded
// by their original window, including when preparing a software-emulated VM.
func containerCommandContext(parent context.Context, args ...string) (context.Context, context.CancelFunc) {
	budget := 12 * time.Second
	if len(args) > 0 && os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		switch args[0] {
		case "run", "start", "restart":
			budget *= 12
		}
	}
	return context.WithTimeout(parent, budget)
}

func cleanupCommand(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", args...).Run()
}
func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestUnmodifiedNginxEABHTTP01Renewal(t *testing.T) { nativeACMEFixture(t, false) }
func nativeACMEFixture(t *testing.T, mutual bool) {
	binary := os.Getenv("GATEBEAM_P3_NATIVE_BINARY")
	if binary == "" {
		t.Fatal("run scripts/check-pki.sh acme: fresh Linux fixture binary required")
	}
	dbContainer := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if dbContainer == "" {
		t.Fatal("owned PG container required")
	}
	requirePinnedNginx(t)
	db := testkit.Postgres(t)
	ctx := context.Background()
	var schema string
	if e := db.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	network := "pki-p3-" + suffix
	command(t, "network", "create", network)
	t.Cleanup(func() { cleanupCommand("network", "rm", network) })
	command(t, "network", "connect", "--alias", "pki-db", network, dbContainer)
	t.Cleanup(func() { cleanupCommand("network", "disconnect", network, dbContainer) })
	cidr := command(t, "network", "inspect", network, "--format", "{{(index .IPAM.Config 0).Subnet}}")
	dir := t.TempDir()
	online := filepath.Join(dir, "online")
	statusOrigin := ""
	if mutual {
		statusOrigin = "http://ca.internal.test:8080"
	}
	if e := (pkicrypto.Bootstrapper{}).Generate(ctx, management.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: online, RootName: "native test root", IntermediateName: "native test issuer", StatusOrigin: statusOrigin}); e != nil {
		t.Fatal(e)
	}
	pkifixture.RotateExistingRoot(t, dir, online, statusOrigin)
	// The offline root is deliberately outside every container mount.
	lab := filepath.Join(dir, "lab")
	if e := os.Mkdir(lab, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(online, filepath.Join(lab, "online")); e != nil {
		t.Fatal(e)
	}
	online = filepath.Join(lab, "online")
	sec, e := secrets.New(filepath.Join(online, "identity.agekey"))
	if e != nil {
		t.Fatal(e)
	}
	recipient, e := secrets.NewRecipient(sec.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	policy, _ := domain.NewPolicy([]string{"a.internal.test", "b.internal.test", "lego.internal.test"}, domain.ServerAuth)
	clientPolicy, _ := domain.NewPolicy([]string{"lego.internal.test"}, domain.ClientAuth)
	grants := management.NewGrantService(security{postgres.NewRunner(db)}, repo.New(), recipient, pkicrypto.Random{}, audit.New(), map[string]domain.Policy{"server": policy, "client": clientPolicy}, nil)
	issue := func(name, directory string) management.EABCredentials {
		t.Helper()
		usage := domain.ServerAuth
		if directory == "client" {
			usage = domain.ClientAuth
		}
		g, e := grants.Authorize(ctx, management.ActorRef{UserID: "test-admin"}, management.GrantSpec{Names: []string{name}, Purpose: usage, Directory: directory, Expires: time.Now().Add(time.Hour)})
		if e != nil {
			t.Fatal(e)
		}
		b, e := grants.IssueEAB(ctx, management.ActorRef{UserID: "test-admin"}, g.ID)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	bindings := map[string]management.EABCredentials{"a": issue("a.internal.test", "server"), "b": issue("b.internal.test", "server"), "lego": issue("lego.internal.test", "server"), "client": issue("lego.internal.test", "client")}
	role := "p3_ca_" + suffix
	if _, e = db.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD 'test-only'"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = db.Exec(c, "DROP OWNED BY "+role)
		_, _ = db.Exec(c, "DROP ROLE "+role)
	})
	for _, q := range []string{"GRANT UPDATE(key_fingerprint) ON pki_issuers TO " + role, "GRANT USAGE ON SCHEMA " + schema + " TO " + role, "GRANT SELECT,INSERT ON pki_issuers,pki_accounts,pki_orders,pki_certificates TO " + role, "GRANT INSERT ON pki_serial_reservations TO " + role, "GRANT SELECT ON pki_restore_quarantine TO " + role, "GRANT SELECT ON pki_principals,pki_grants,pki_eab,pki_eab_envelopes TO " + role, "GRANT UPDATE(consumed) ON pki_eab TO " + role, "GRANT UPDATE(thumbprint,public_key,status,contacts,revision) ON pki_accounts TO " + role, "GRANT UPDATE(status,challenges,revision) ON pki_orders TO " + role, "GRANT SELECT,INSERT ON pki_revocations,pki_status_certificates,pki_crl_versions TO " + role, "GRANT SELECT,INSERT ON pki_root_crl_state TO " + role, "GRANT UPDATE(number,der,revoked_serials) ON pki_root_crl_state TO " + role, "GRANT UPDATE(number) ON pki_crl_versions TO " + role, "GRANT SELECT,INSERT,DELETE ON pki_nonces TO " + role} {
		if _, e = db.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	config, _ := json.Marshal(fixtureConfig{DSN: "postgres://" + role + ":test-only@pki-db:5432/gatebeam?sslmode=disable&search_path=" + schema, Network: cidr, NativeStatus: mutual})
	write(t, filepath.Join(lab, "fixture.json"), config)
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native transport"}, DNSNames: []string{"ca.internal.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(lab, "transport.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, filepath.Join(lab, "transport-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	start := func(name, alias string, extra ...string) string {
		t.Helper()
		full := "p3-" + name + "-" + suffix
		args := []string{"run", "-d", "--name", full, "--network", network, "--network-alias", alias, "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1"}
		args = append(args, extra...)
		command(t, args...)
		t.Cleanup(func() {
			if t.Failed() {
				t.Log(command(t, "logs", "--tail", "50", full))
			}
			cleanupCommand("rm", "-f", full)
		})
		return full
	}
	ca := start("ca", "ca.internal.test", "-p", "127.0.0.1::8443", "-p", "127.0.0.1::8080", "-v", lab+":/lab:ro", "-v", binary+":/fixture:ro", "-e", "GATEBEAM_P3_CA_FIXTURE=1", "--stop-signal", "SIGTERM", "--entrypoint", "/fixture", nginxImage)
	sampleClock := func() {
		before := time.Now().UTC()
		native := command(t, "exec", "-e", "GATEBEAM_CLOCK_SAMPLE=1", ca, "/fixture")
		after := time.Now().UTC()
		value, err := time.Parse(time.RFC3339Nano, native)
		if err != nil {
			t.Fatal("invalid body-free clock sample")
		}
		t.Logf("clock sample host_before=%s native=%s host_after=%s native-minus-host=[%s,%s]", before.Format(time.RFC3339Nano), native, after.Format(time.RFC3339Nano), value.Sub(after), value.Sub(before))
	}
	sampleClock()
	t.Cleanup(func() {
		if t.Failed() {
			sampleClock()
		}
	})
	caAddress := command(t, "port", ca, "8443/tcp")
	transportTrust := x509.NewCertPool()
	transportTrust.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	ht := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: transportTrust, MinVersion: tls.VersionTLS12}, DialContext: func(c context.Context, n, a string) (net.Conn, error) {
		if a != "ca.internal.test:8443" {
			return nil, fmt.Errorf("unexpected CA endpoint")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(c, n, caAddress)
	}}
	defer ht.CloseIdleConnections()
	hc := &http.Client{Transport: ht, Timeout: 10 * time.Second}
	deadline := time.Now().Add(8 * time.Second)
	for {
		resp, e := hc.Get("https://ca.internal.test:8443/acme/server/directory")
		if e == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("CA fixture did not become ready", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	rootPEM, e := os.ReadFile(filepath.Join(online, "root.pem"))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	if mutual {
		write(t, filepath.Join(lab, "business.crl"), nativeCRL(t, online, nil))
	}
	addresses := map[string]string{}
	containers := map[string]string{}
	for _, name := range []string{"a", "b"} {
		state := filepath.Join(lab, "state-"+name)
		if e = os.Mkdir(state, 0777); e != nil {
			t.Fatal(e)
		}
		if e = os.Chmod(state, 0777); e != nil {
			t.Fatal(e)
		}
		write(t, filepath.Join(lab, name+".eab"), []byte(bindings[name].HMAC))
		conf := fmt.Sprintf(`load_module /usr/lib/nginx/modules/ngx_http_acme_module.so;
worker_processes 1;
error_log /dev/stderr info;
events { worker_connections 128; }
http {
 access_log off;
 resolver 127.0.0.11 ipv6=off valid=1s;
 acme_issuer gatebeam { uri https://ca.internal.test:8443/acme/server/directory; accept_terms_of_service; challenge http-01; state_path /state; external_account_key %s /lab/%s.eab; ssl_trusted_certificate /lab/transport.pem; ssl_verify on; }
 server { listen 80; server_name %s.internal.test; location / { return 404; } }
 server { listen 443 ssl; server_name %s.internal.test; acme_certificate gatebeam; ssl_certificate $acme_certificate; ssl_certificate_key $acme_certificate_key; ssl_certificate_cache max=4 inactive=1s valid=1s; location / { return 200 'native-ok'; } }
}`, bindings[name].KeyID, name, name, name)
		if mutual {
			conf = strings.Replace(conf, "server_name "+name+".internal.test; acme_certificate gatebeam;", "server_name "+name+".internal.test shop.example.test; acme_certificate gatebeam "+name+".internal.test; ssl_client_certificate /lab/root.pem; ssl_verify_client on; ssl_verify_depth 2; ssl_ocsp on; ssl_ocsp_cache off; ssl_session_cache off; ssl_session_tickets off; ssl_crl /lab/business.crl; if ($host != shop.example.test) { return 421; }", 1)
			conf = strings.Replace(conf, "access_log off;", "log_format p6 'p6-connection=$connection status=$status'; access_log /dev/stdout p6;", 1)
			conf = strings.Replace(conf, "return 200 'native-ok';", "return 200 '$host|$ssl_server_name|$ssl_client_verify';", 1)
			conf = strings.Replace(conf, "listen 443 ssl;", "listen 443 ssl default_server;", 1)
			// Force NEW business TLS connections for OCSP revocation checks:
			// current Nginx enables upstream keepalive by default. This fixture
			// makes no claim about terminating existing streams or cached status.
			conf = strings.Replace(conf, "http {", "http { keepalive_timeout 0; server {listen 443 ssl; server_name rejected.internal.test; ssl_reject_handshake on; ssl_client_certificate /lab/root.pem; ssl_verify_client on; ssl_verify_depth 2; ssl_ocsp on; ssl_ocsp_cache off; ssl_session_cache off; ssl_session_tickets off; ssl_crl /lab/business.crl; return 421;} ", 1)
		}
		write(t, filepath.Join(lab, name+".conf"), []byte(conf))
		if !mutual {
			write(t, filepath.Join(lab, "business.crl"), []byte("unused"))
		}
		full := start(name, name+".internal.test", "-p", "127.0.0.1::443", "-v", filepath.Join(lab, name+".conf")+":/lab/"+name+".conf:ro", "-v", filepath.Join(lab, name+".eab")+":/lab/"+name+".eab:ro", "-v", filepath.Join(lab, "transport.pem")+":/lab/transport.pem:ro", "-v", state+":/state", "-v", filepath.Join(lab, "business.crl")+":/lab/business.crl:ro", "-v", filepath.Join(online, "root.pem")+":/lab/root.pem:ro", "--entrypoint", "nginx", nginxImage, "-c", "/lab/"+name+".conf", "-g", "daemon off;")
		containers[name] = full
		addresses[name] = command(t, "port", full, "443/tcp")
	}
	peer := func(name string) ([]byte, error) {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{RootCAs: roots, ServerName: name + ".internal.test", MinVersion: tls.VersionTLS12}}
		c, e := d.DialContext(ctx, "tcp", addresses[name])
		if e != nil {
			return nil, e
		}
		defer c.Close()
		return append([]byte(nil), c.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw...), nil
	}
	waitPeer := func(name string, previous []byte, limit time.Duration) []byte {
		t.Helper()
		end := time.Now().Add(limit)
		for {
			der, e := peer(name)
			if e == nil && !bytes.Equal(der, previous) {
				return der
			}
			if time.Now().After(end) {
				t.Fatalf("%s certificate deadline: %v", name, e)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	firstA := waitPeer("a", nil, 10*time.Second)
	firstB := waitPeer("b", nil, 10*time.Second)
	if bytes.Equal(firstA, firstB) {
		t.Fatal("A/B shared leaf")
	}
	t.Log("unmodified Nginx 1.31.8/module 0.4.1: A/B EAB HTTP-01 issuance and trusted TLS PASS")
	if mutual {
		verifyBusinessMTLS(t, addresses, roots)
		clientIdentityClosure(t, db, hc, roots, rootPEM, lab, online, bindings["client"], addresses, containers, ca, start)
		return
	}
	// Unmodified lego uses a standard webroot provider served on actual port 80.
	web := filepath.Join(lab, "web")
	if e = os.Mkdir(web, 0755); e != nil {
		t.Fatal(e)
	}
	write(t, filepath.Join(lab, "lego.conf"), []byte("events {} http { access_log off; server { listen 80; server_name lego.internal.test; root /web; } }"))
	start("lego", "lego.internal.test", "-v", filepath.Join(lab, "lego.conf")+":/lab/lego.conf:ro", "-v", web+":/web:ro", "--entrypoint", "nginx", nginxImage, "-c", "/lab/lego.conf", "-g", "daemon off;")
	for _, directory := range []string{"server", "client"} {
		binding := bindings["lego"]
		if directory == "client" {
			binding = bindings["client"]
		}
		runLego(t, hc, web, directory, binding, roots)
	}
	secondA := waitPeer("a", firstA, 55*time.Second)
	secondB := waitPeer("b", firstB, 5*time.Second)
	t.Log("real wall-clock automatic renewal and live TLS replacement A/B PASS")
	command(t, "stop", "-t", "1", ca)
	command(t, "start", ca)
	caAddress = command(t, "port", ca, "8443/tcp")
	ht.CloseIdleConnections()
	// The running standard clients retain their account keys; the CA reloads only
	// persisted state. The next real automatic renewal must succeed without EAB.
	end := time.Now().Add(5 * time.Second)
	for {
		resp, err := hc.Get("https://ca.internal.test:8443/acme/server/directory")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(end) {
			t.Fatal("restarted CA not ready", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	thirdA := waitPeer("a", secondA, 40*time.Second)
	thirdB := waitPeer("b", secondB, 5*time.Second)
	t.Log("restarted self-CA + existing Nginx accounts automatic renewal PASS")
	command(t, "stop", "-t", "1", ca)
	for _, name := range []string{"a", "b"} {
		command(t, "restart", "-t", "1", containers[name])
		addresses[name] = command(t, "port", containers[name], "443/tcp")
		end := time.Now().Add(4 * time.Second)
		for {
			got, e := peer(name)
			if e == nil {
				want := thirdA
				if name == "b" {
					want = thirdB
				}
				if !bytes.Equal(got, want) {
					t.Fatal("restart changed saved certificate")
				}
				break
			}
			if time.Now().After(end) {
				t.Fatal("offline CA restart lost certificate", e)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Log("CA offline + Nginx restart persisted account/certificate state PASS")
	var count int
	if e = db.QueryRow(ctx, "SELECT count(*) FROM pki_certificates").Scan(&count); e != nil || count < 8 {
		t.Fatal("CA persisted issuance missing", e, count)
	}
}

type legoUser struct {
	k       crypto.Signer
	account *legoacme.ExtendedAccount
}

func (u *legoUser) GetEmail() string                           { return "" }
func (u *legoUser) GetRegistration() *legoacme.ExtendedAccount { return u.account }
func (u *legoUser) GetPrivateKey() crypto.Signer               { return u.k }
func runLego(t *testing.T, hc *http.Client, web, directory string, b management.EABCredentials, roots *x509.CertPool) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	u := &legoUser{k: k}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = "https://ca.internal.test:8443/acme/" + directory + "/directory"
	cfg.HTTPClient = hc
	client, e := lego.NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	provider, e := webroot.NewHTTPProvider(web)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Challenge.SetHTTP01Provider(provider); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	u.account, e = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{Kid: b.KeyID, HmacEncoded: b.HMAC, TermsOfServiceAgreed: true})
	if e != nil {
		t.Fatal("lego EAB", e)
	}
	issued, e := client.Certificate.Obtain(ctx, certificate.ObtainRequest{KeyType: certcrypto.EC256, Domains: []string{"lego.internal.test"}, Bundle: true})
	if e != nil {
		t.Fatal("lego issuance", e)
	}
	block, rest := pem.Decode(issued.Certificate)
	if block == nil {
		t.Fatal("missing lego leaf")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	chain := x509.NewCertPool()
	chain.AppendCertsFromPEM(rest)
	usage := x509.ExtKeyUsageServerAuth
	if directory == "client" {
		usage = x509.ExtKeyUsageClientAuth
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: chain, KeyUsages: []x509.ExtKeyUsage{usage}, DNSName: "lego.internal.test"}); e != nil {
		t.Fatalf("lego chain/purpose: %v; verify_utc=%s leaf_not_before=%s leaf_not_after=%s", e, time.Now().UTC().Format(time.RFC3339Nano), leaf.NotBefore.Format(time.RFC3339Nano), leaf.NotAfter.Format(time.RFC3339Nano))
	}
	if _, e = client.Certificate.Obtain(ctx, certificate.ObtainRequest{KeyType: certcrypto.EC256, Domains: []string{"unauthorized.internal.test"}}); e == nil {
		t.Fatal("lego unauthorized name issued")
	}
	wrong := t.TempDir()
	badProvider, e := webroot.NewHTTPProvider(wrong)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Challenge.SetHTTP01Provider(badProvider); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Certificate.Obtain(ctx, certificate.ObtainRequest{KeyType: certcrypto.EC256, Domains: []string{"lego.internal.test"}}); e == nil {
		t.Fatal("missing real HTTP-01 proof issued")
	}
	t.Log("unmodified lego 5.6.0", directory, "HTTP-01 exact SAN/purpose positive and forbidden name negative PASS")
}
