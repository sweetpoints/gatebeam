//go:build integration

package pki_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/modules/pki"
	management "gatebeam/internal/modules/pki/application"
	statusapp "gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"golang.org/x/crypto/ocsp"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This fixture exercises unmodified Nginx's client-certificate OCSP separately
// from proxy_ssl_crl for its upstream server. All state comes from real PG.
func TestNativeNginxRevocationAndResumption(t *testing.T) {
	requirePinnedNginx(t)
	openssl := os.Getenv("GATEBEAM_TEST_OPENSSL")
	if openssl == "" {
		t.Fatal("GATEBEAM_TEST_OPENSSL required")
	}
	runSSL := func(args []string, input string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, openssl, args...)
		cmd.Stdin = strings.NewReader(input)
		b, e := cmd.CombinedOutput()
		lines := []string{}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "HTTP/") || strings.Contains(line, "New,") || strings.Contains(line, "Reused,") || strings.Contains(line, "error") || strings.Contains(line, "Verification:") || strings.Contains(line, "Verify return") || strings.Contains(line, "OpenSSL") || strings.Contains(line, "Could not") {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n"), e
	}
	version, e := runSSL([]string{"version"}, "")
	if e != nil {
		t.Fatal(e)
	}
	t.Log(strings.TrimSpace(version))
	db := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(db)
	store := repo.New()
	dir := t.TempDir()
	online := filepath.Join(dir, "online")
	lab := filepath.Join(dir, "lab")
	if e = os.Mkdir(lab, 0700); e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("pki-p4-%d", time.Now().UnixNano())
	command(t, "network", "create", name)
	t.Cleanup(func() { cleanupCommand("network", "rm", name) })
	listenHost, statusHost, localStatusHost := "0.0.0.0", "host.docker.internal", "127.0.0.1"
	if runtime.GOOS == "linux" {
		// Native Nginx resolves certificate AIA through Docker DNS; Linux does
		// not provide Desktop's host.docker.internal record. Use the owned
		// network gateway as the standard HTTP OCSP origin and bind only there.
		listenHost = command(t, "network", "inspect", name, "--format", "{{(index .IPAM.Config 0).Gateway}}")
		statusHost, localStatusHost = listenHost, listenHost
	}
	listener, e := net.Listen("tcp", net.JoinHostPort(listenHost, "0"))
	if e != nil {
		t.Fatal(e)
	}
	statusOrigin := "http://" + net.JoinHostPort(statusHost, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	localStatusOrigin := "http://" + net.JoinHostPort(localStatusHost, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	if e = (pkicrypto.Bootstrapper{}).Generate(ctx, management.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: online, RootName: "native status root", IntermediateName: "native status intermediate", StatusOrigin: statusOrigin}); e != nil {
		t.Fatal(e)
	}
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	if e = management.NewRegistry(tx, store).Register(ctx, issuer.Metadata(), issuer.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	issuer.StatusOrigin = statusOrigin
	service := statusapp.New(tx, store, pkicrypto.NewStatusSigner(issuer), nil)
	var handlers atomic.Value
	statusConfig := pki.Config{ServerNames: []string{"native.internal.test"}, ClientNames: []string{"native.internal.test"}, Origin: "https://ca.internal.test", StatusOrigin: statusOrigin, IdentityFile: filepath.Join(online, "identity.agekey"), RootCRLFile: filepath.Join(online, "root.crl.der"), RootOCSPCertificateFile: filepath.Join(online, "root-ocsp.pem"), RootOCSPSignerFile: filepath.Join(online, "root-ocsp.age"), ValidationNetworks: []string{"10.0.0.0/8"}}
	restartStatus := func() {
		t.Helper()
		ca, e := pki.NewServer(statusConfig, db, issuer)
		if e != nil {
			t.Fatal(e)
		}
		if e = ca.RegisterStatus(ctx, db); e != nil {
			t.Fatal(e)
		}
		handlers.Store(ca.StatusHandler())
	}
	restartStatus()
	var outage atomic.Bool
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() {
			http.Error(w, "fixture outage", 503)
			return
		}
		handlers.Load().(http.Handler).ServeHTTP(w, r)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Chain[0].Raw})
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})
	write(t, filepath.Join(lab, "root.pem"), rootPEM)
	write(t, filepath.Join(lab, "trust.pem"), append(append([]byte{}, issuerPEM...), rootPEM...))
	issue := func(id string, usage domain.Usage, persist bool) *x509.Certificate {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"native.internal.test"}}, key)
		if e != nil {
			t.Fatal(e)
		}
		policy, _ := domain.NewPolicy([]string{"native.internal.test"}, usage)
		serial, e := pkicrypto.NewSerial()
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC().Truncate(time.Second)
		der, e := issuer.SignCSR(csr, policy, []string{"native.internal.test"}, serial, now, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		pkcs8, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		write(t, filepath.Join(lab, id+".pem"), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), issuerPEM...))
		write(t, filepath.Join(lab, id+"-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
		if persist {
			directory := "server"
			if usage == domain.ClientAuth {
				directory = "client"
			}
			e = tx.Within(ctx, func(sc transaction.Scope) error {
				if e := store.InsertGrant(sc, management.Grant{ID: id, Principal: domain.Principal{ID: id, Names: []string{"native.internal.test"}, Usage: usage, Directory: directory, Expires: now.Add(time.Hour)}}); e != nil {
					return e
				}
				if e := store.InsertAccount(sc, domain.Account{ID: id, PrincipalID: id, Directory: directory, Thumbprint: id, Key: []byte("public fixture"), Status: "valid"}); e != nil {
					return e
				}
				if e := store.InsertOrder(sc, domain.Order{ID: id, AccountID: id, Directory: directory, Names: []string{"native.internal.test"}, Usage: usage, Status: "valid", Expires: now.Add(time.Hour), Revision: 1, Challenges: []domain.Challenge{}}); e != nil {
					return e
				}
				sn := domain.Serial(fmt.Sprintf("%040x", serial))
				if e := store.ReserveSerial(sc, issuer.Metadata().ID, sn); e != nil {
					return e
				}
				return store.InsertCertificate(sc, domain.IssuedCertificate{OrderID: id, IssuerID: issuer.Metadata().ID, Serial: sn, DER: der, Chain: der, NotBefore: now, NotAfter: now.Add(time.Hour)})
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		return leaf
	}
	serverLeaf := issue("server", domain.ServerAuth, true)
	client := issue("client", domain.ClientAuth, true)
	issue("unknown", domain.ClientAuth, false)
	issue("parent-client", domain.ClientAuth, true)
	admin := statusapp.NewManagement(security{tx}, store, audit.New(), pkicrypto.Random{}, nil)
	rootCRL, e := os.ReadFile(filepath.Join(online, "root.crl.der"))
	if e != nil {
		t.Fatal(e)
	}
	crlNumber := 0
	crlName := ""
	publishCRL := func(includeRoot bool) {
		t.Helper()
		der, e := service.CRL(ctx, issuer.Metadata().ID)
		if e != nil {
			t.Fatal(e)
		}
		bundle := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
		if includeRoot {
			bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: rootCRL})...)
		}
		// Immutable generation files match the production material lifecycle.
		// Nginx SSL object inheritance cannot mistake this for the old CRL.
		crlNumber++
		crlName = fmt.Sprintf("bundle-%d.crl", crlNumber)
		write(t, filepath.Join(lab, crlName), bundle)
	}
	publishCRL(true)
	config := `worker_processes 1; pid /tmp/nginx.pid; error_log /dev/stderr info;
 events {worker_connections 128;}
 http {access_log off; resolver 127.0.0.11 valid=5s; resolver_timeout 1s;
 ssl_certificate /lab/server.pem; ssl_certificate_key /lab/server-key.pem;
 ssl_protocols TLSv1.2 TLSv1.3; ssl_session_cache off; ssl_session_tickets off;
 ssl_client_certificate /lab/trust.pem; ssl_verify_depth 2;
 server {listen 8443 ssl; ssl_verify_client on; ssl_ocsp on; ssl_ocsp_cache shared:status:1m; location / {root /lab;try_files /ok.txt =404;}}
 server {listen 8444 ssl; ssl_verify_client on; ssl_ocsp on; ssl_ocsp_cache off; location / {root /lab;try_files /ok.txt =404;}}
 server {listen 9443 ssl; location / {root /lab;try_files /ok.txt =404;}}
 server {listen 8080;location / {proxy_pass https://127.0.0.1:9443; proxy_ssl_verify on;proxy_ssl_trusted_certificate /lab/trust.pem;proxy_ssl_crl /lab/CRLFILE;proxy_ssl_verify_depth 2;proxy_ssl_server_name on;proxy_ssl_name native.internal.test;proxy_ssl_session_reuse off;}}
 }
`
	write(t, filepath.Join(lab, "nginx.conf"), []byte(strings.ReplaceAll(config, "CRLFILE", crlName)))
	write(t, filepath.Join(lab, "ok.txt"), []byte("native-ok"))
	// Fixture files are public certificates or test-only leaf keys. The offline
	// root and online issuer private keys are outside this container mount.
	if e = os.Chmod(lab, 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(lab, "ok.txt"), 0644); e != nil {
		t.Fatal(e)
	}
	command(t, "run", "-d", "--name", name, "--network", name, "--memory", "192m", "--cpus", "1", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-p", "127.0.0.1::8443", "-p", "127.0.0.1::8444", "-p", "127.0.0.1::8080", "-v", lab+":/lab:ro", "--entrypoint", "nginx", nginxImage, "-c", "/lab/nginx.conf", "-g", "daemon off;")
	t.Cleanup(func() { cleanupCommand("rm", "-f", name) })
	cached := command(t, "port", name, "8443/tcp")
	cold := command(t, "port", name, "8444/tcp")
	proxy := command(t, "port", name, "8080/tcp")
	ssl := func(addr, id, tls string, extra ...string) string {
		t.Helper()
		args := []string{"s_client", "-ign_eof", "-connect", addr, "-servername", "native.internal.test", "-verify_hostname", "native.internal.test", "-verify_return_error", "-CAfile", filepath.Join(lab, "root.pem"), "-cert", filepath.Join(lab, id+".pem"), "-key", filepath.Join(lab, id+"-key.pem"), "-cert_chain", filepath.Join(lab, "trust.pem"), tls}
		args = append(args, extra...)
		out, e := runSSL(args, "GET / HTTP/1.0\r\nHost: native.internal.test\r\n\r\n")
		if e != nil {
			t.Fatalf("TLS client failed: %v %s", e, out)
		}
		return out
	}
	// Nginx reads /lab as an unprivileged worker; permit traversal of this isolated
	// fixture directory without exposing any CA private material.
	command(t, "exec", name, "nginx", "-t", "-c", "/lab/nginx.conf")
	for _, version := range []string{"-tls1_2", "-tls1_3"} {
		out := ssl(cached, "client", version)
		if !strings.Contains(out, "200 OK") {
			t.Fatalf("good client rejected: %s\n%s", out, command(t, "logs", name))
		}
	}
	restartStatus()
	if out := ssl(cold, "parent-client", "-tls1_3"); !strings.Contains(out, "200 OK") {
		t.Fatal("root delegation restart failed", out)
	}
	if out := ssl(cold, "unknown", "-tls1_3"); !strings.Contains(out, "400 Bad Request") {
		t.Fatal("unknown client accepted", out)
	}
	outage.Store(true)
	if out := ssl(cached, "client", "-tls1_3"); !strings.Contains(out, "200 OK") {
		t.Fatal("fresh cache not honored", out)
	}
	if out := ssl(cold, "client", "-tls1_3"); !strings.Contains(out, "400 Bad Request") {
		t.Fatal("uncached outage accepted", out)
	}
	outage.Store(false)
	session := filepath.Join(dir, "tls12.session")
	if out := ssl(cold, "client", "-tls1_2", "-sess_out", session); !strings.Contains(out, "200 OK") {
		t.Fatal(out)
	}
	if e = admin.Revoke(ctx, management.ActorRef{UserID: "admin"}, string(issuer.Metadata().ID), fmt.Sprintf("%040x", client.SerialNumber), 1); e != nil {
		t.Fatal(e)
	}
	// Commit disable separately from leaf revocation, then start two fresh
	// OS processes from encrypted disk material and the same committed database.
	if e = tx.Within(ctx, func(sc transaction.Scope) error {
		if _, e := store.Principal(sc, "client"); e != nil {
			return e
		}
		return store.DisablePrincipal(sc, "client")
	}); e != nil {
		t.Fatal(e)
	}
	var schema string
	if e = db.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		base, stopProcess := startStatusProcess(t, statusProcessConfig{DatabaseURL: os.Getenv("GATEBEAM_TEST_DATABASE_URL"), Schema: schema, Online: online, Config: statusConfig})
		request, e := ocsp.CreateRequest(client, issuer.Certificate, nil)
		if e != nil {
			t.Fatal(e)
		}
		response, e := (&http.Client{Timeout: time.Second}).Get(base + "/ocsp/" + base64.StdEncoding.EncodeToString(request))
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := ocsp.ParseResponse(body, issuer.Certificate)
		if e != nil || parsed.Status != ocsp.Revoked {
			t.Fatal("process restart lost revocation", e)
		}
		parentRequest, e := ocsp.CreateRequest(issuer.Certificate, issuer.Chain[0], nil)
		if e != nil {
			t.Fatal(e)
		}
		response, e = (&http.Client{Timeout: time.Second}).Get(base + "/ocsp/" + base64.StdEncoding.EncodeToString(parentRequest))
		if e != nil {
			t.Fatal(e)
		}
		body, e = io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		parsed, e = ocsp.ParseResponse(body, issuer.Chain[0])
		if e != nil || parsed.Status != ocsp.Good {
			t.Fatal("process restart lost root delegation", e)
		}
		stopProcess()
	}
	for _, version := range []string{"-tls1_2", "-tls1_3"} {
		extra := []string{"-reconnect"}
		if version == "-tls1_2" {
			if _, e := os.Stat(session); e == nil {
				extra = append(extra, "-sess_in", session)
			} else if !os.IsNotExist(e) {
				t.Fatal(e)
			} else {
				t.Log("TLS1.2 server did not issue a resumable session with cache/tickets disabled; -reconnect attempts must perform full verification")
			}
		}
		out := ssl(cold, "client", version, extra...)
		if !strings.Contains(out, "400 Bad Request") || strings.Contains(out, "Reused,") {
			t.Fatal("resumption attempt bypassed disabled session reuse", out)
		}
	}
	clientHTTP := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	getProxy := func() int {
		t.Helper()
		r, e := clientHTTP.Get("http://" + proxy)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		return r.StatusCode
	}
	if code := getProxy(); code != 200 {
		t.Fatal("good upstream rejected", code, command(t, "logs", name))
	}
	reload := func() {
		t.Helper()
		write(t, filepath.Join(lab, "nginx.conf"), []byte(strings.ReplaceAll(config, "CRLFILE", crlName)))
		old := strings.Fields(command(t, "exec", name, "cat", "/proc/1/task/1/children"))
		command(t, "exec", name, "nginx", "-s", "reload", "-c", "/lab/nginx.conf")
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			current := strings.Fields(command(t, "exec", name, "cat", "/proc/1/task/1/children"))
			gone := true
			for _, p := range old {
				for _, q := range current {
					if p == q {
						gone = false
					}
				}
			}
			if gone {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("old nginx worker did not exit after reload")
	}
	publishCRL(false)
	reload()
	if code := getProxy(); code != 502 {
		t.Fatal("missing root CRL accepted", code)
	}
	publishCRL(true)
	reload()
	if code := getProxy(); code != 200 {
		t.Fatal("full CRL chain rejected", code, command(t, "logs", name))
	}
	if e = admin.Revoke(ctx, management.ActorRef{UserID: "admin"}, string(issuer.Metadata().ID), fmt.Sprintf("%040x", serverLeaf.SerialNumber), 1); e != nil {
		t.Fatal(e)
	}
	publishCRL(true)
	reload()
	if code := getProxy(); code != 502 {
		t.Fatal("revoked upstream accepted", code)
	}
	// Revoke the intermediate using only the offline root ceremony. The
	// running root-delegated responder must publish fresh revoked, not cached good.
	offline := filepath.Join(dir, "offline")
	for filename, data := range map[string]string{"index.txt": "", "crlnumber": "02\n", "openssl.cnf": "[ca]\ndefault_ca=root\n[root]\ndatabase=index.txt\ncrlnumber=crlnumber\ncertificate=root.pem\nprivate_key=root-key.pem\ndefault_md=sha384\ndefault_crl_days=30\n"} {
		write(t, filepath.Join(offline, filename), []byte(data))
	}
	offlineRun := func(args ...string) {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(c, openssl, args...)
		cmd.Dir = offline
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("offline root status: %v %s", e, b)
		}
	}
	offlineRun("ca", "-config", "openssl.cnf", "-valid", filepath.Join(online, "issuer.pem"))
	offlineRun("ca", "-config", "openssl.cnf", "-revoke", filepath.Join(online, "issuer.pem"), "-crl_reason", "keyCompromise")
	offlineRun("ca", "-config", "openssl.cnf", "-gencrl", "-out", "revoked.pem")
	offlineRun("crl", "-in", "revoked.pem", "-outform", "DER", "-out", filepath.Join(online, "root.crl.der"))
	requestDER, e := ocsp.CreateRequest(issuer.Certificate, issuer.Chain[0], nil)
	if e != nil {
		t.Fatal(e)
	}
	response, e := clientHTTP.Get(localStatusOrigin + "/ocsp/" + base64.StdEncoding.EncodeToString(requestDER))
	if e != nil {
		t.Fatal(e)
	}
	responseDER, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	signed, e := ocsp.ParseResponse(responseDER, issuer.Chain[0])
	if e != nil || signed.Status != ocsp.Revoked || signed.Certificate == nil {
		t.Fatal("root delegated revocation invalid", e)
	}
	if out := ssl(cold, "parent-client", "-tls1_3"); !strings.Contains(out, "400 Bad Request") {
		t.Fatal("revoked intermediate accepted by full-chain OCSP", out)
	}
	// A signed but older root CRL cannot reverse an observed revocation.
	write(t, filepath.Join(online, "root.crl.der"), rootCRL)
	response, e = clientHTTP.Get(localStatusOrigin + "/ocsp/" + base64.StdEncoding.EncodeToString(requestDER))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("root CRL rollback accepted", response.StatusCode)
	}
	// Even a newly numbered CRL from an accidentally restored empty offline
	// index cannot forget a revocation already observed in the online authority.
	write(t, filepath.Join(offline, "index.txt"), nil)
	offlineRun("ca", "-config", "openssl.cnf", "-gencrl", "-out", "forgotten.pem")
	offlineRun("crl", "-in", "forgotten.pem", "-outform", "DER", "-out", filepath.Join(online, "root.crl.der"))
	response, e = clientHTTP.Get(localStatusOrigin + "/ocsp/" + base64.StdEncoding.EncodeToString(requestDER))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("new root CRL forgot permanent revocation", response.StatusCode)
	}
	if bytes.Contains([]byte(command(t, "logs", name)), []byte("Segmentation")) {
		t.Fatal("native server crashed")
	}
	t.Log("PASS full-chain ssl_ocsp on + root and intermediate delegated OCSP good/revoked/unknown/outage/fresh cache; TLS1.2/1.3 resumption attempts cannot bypass disabled reuse; complete CRL chain good/revoked/missing-root")
}
