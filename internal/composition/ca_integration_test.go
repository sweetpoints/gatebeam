//go:build integration

package composition

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/modules/pki"
	"gatebeam/internal/modules/pki/application"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/testkit"
	"github.com/jackc/pgx/v5"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCAProcessRegistersIssuerAndBootstrapsWithoutBusinessLeaf(t *testing.T) {
	db := testkit.Postgres(t)
	// This coordinates role setup, issuer creation and an owned CA lifetime;
	// individual production operations and the HTTP client's one-second bound
	// remain independent of this aggregate fixture budget.
	emulated := os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm"
	fixtureBudget := 20 * time.Second
	if emulated {
		fixtureBudget *= 12
	}
	ctx, cancel := context.WithTimeout(t.Context(), fixtureBudget)
	defer cancel()
	var schema string
	if e := db.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 8)
	if _, e := rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	role := "pki_ca_" + hex.EncodeToString(nonce)
	reader := role + "_reader"
	for _, r := range []string{role, reader} {
		if _, e := db.Exec(ctx, "CREATE ROLE "+pgx.Identifier{r}.Sanitize()+" LOGIN PASSWORD 'test-only'"); e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, r := range []string{role, reader} {
			if _, e := db.Exec(c, "DROP OWNED BY "+pgx.Identifier{r}.Sanitize()); e != nil {
				t.Error(e)
			}
			if _, e := db.Exec(c, "DROP ROLE "+pgx.Identifier{r}.Sanitize()); e != nil {
				t.Error(e)
			}
		}
	})
	for _, r := range []string{role, reader} {
		if _, e := db.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+pgx.Identifier{r}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	for _, query := range []string{"GRANT UPDATE(key_fingerprint) ON pki_issuers TO " + role, "GRANT SELECT,INSERT ON pki_issuers TO " + role, "GRANT INSERT ON pki_serial_reservations TO " + role, "GRANT SELECT ON pki_restore_quarantine TO " + role, "GRANT SELECT ON pki_issuers TO " + reader, "GRANT SELECT ON pki_principals,pki_grants,pki_eab TO " + role, "GRANT UPDATE(consumed) ON pki_eab TO " + role, "GRANT SELECT,INSERT ON pki_accounts TO " + role, "GRANT UPDATE(thumbprint,public_key,status,contacts,revision) ON pki_accounts TO " + role, "GRANT SELECT,INSERT ON pki_revocations,pki_status_certificates,pki_crl_versions TO " + role, "GRANT SELECT,INSERT ON pki_root_crl_state TO " + role, "GRANT UPDATE(number,der,revoked_serials) ON pki_root_crl_state TO " + role, "GRANT UPDATE(number) ON pki_crl_versions TO " + role, "GRANT SELECT,INSERT,DELETE ON pki_nonces TO " + role, "GRANT SELECT,INSERT ON pki_orders,pki_certificates TO " + role, "GRANT UPDATE(status,challenges,revision) ON pki_orders TO " + role} {
		if _, e := db.Exec(ctx, query); e != nil {
			t.Fatal(e)
		}
	}
	base := t.TempDir()
	offline, online := filepath.Join(base, "offline"), filepath.Join(base, "online")
	statusListener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	statusAddr := statusListener.Addr().String()
	statusListener.Close()
	if e := pki.BootstrapOffline(ctx, application.BootstrapCommand{RootDirectory: offline, OnlineDirectory: online, RootName: "test offline root", IntermediateName: "test online issuer", StatusOrigin: "http://" + statusAddr}); e != nil {
		t.Fatal(e)
	}
	write := func(name string, b []byte) string {
		t.Helper()
		path := filepath.Join(base, name)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	// Bootstrap the private transport under the declared internal CA trust.
	// The connecting standard TLS client receives only public trust material.
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bootstrap transport"}, DNSNames: []string{"ca.internal.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, issuer.Certificate, &k.PublicKey, issuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		t.Fatal(e)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...)
	certFile := write("bootstrap.pem", chain)
	keyFile := write("bootstrap-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	connection := db.Config().ConnConfig.Copy()
	connection.User = role
	connection.Password = "test-only"
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword(role, "test-only"), Host: net.JoinHostPort(connection.Host, strconv.Itoa(int(connection.Port))), Path: connection.Database}
	params := url.Values{"sslmode": {"disable"}, "search_path": {schema}}
	dsn.RawQuery = params.Encode()
	dbFile := write("ca-database", []byte(dsn.String()))
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()

	cfg := bootstrap.Config{CARootOCSPCertificateFile: filepath.Join(online, "root-ocsp.pem"), CARootOCSPSignerFile: filepath.Join(online, "root-ocsp.age"), CAStatusListen: statusAddr, CAStatusOrigin: "http://" + statusAddr, CARootCRLFile: filepath.Join(online, "root.crl.der"), CAValidationNetworks: []string{"10.0.0.0/24"}, DatabaseFile: dbFile, CAListen: addr, CAOrigin: "https://" + addr, CAHostname: "ca.internal.test", CATLSCertificateFile: certFile, CATLSKeyFile: keyFile, CACertificateFile: filepath.Join(online, "issuer.pem"), CARootFile: filepath.Join(online, "root.pem"), CASignerFile: filepath.Join(online, "issuer.age"), CAIdentityFile: filepath.Join(online, "identity.agekey"), CAServerNames: []string{"server.internal.test"}, CAClientNames: []string{"client.internal.test"}}
	serving, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- Run(serving, "ca", cfg) }()
	defer stop()
	trust := x509.NewCertPool()
	c, e := x509.ParseCertificate(issuer.Chain[0].Raw)
	if e != nil {
		t.Fatal(e)
	}
	trust.AddCert(c)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust, ServerName: "ca.internal.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: time.Second, Transport: transport}
	reached := false
	startup := time.Now()
	startupDeadline := startup.Add(60 * time.Second)
	for attempt := 0; ; attempt++ {
		if !emulated && attempt >= 50 || emulated && time.Now().After(startupDeadline) {
			break
		}
		response, e := client.Get("https://" + addr + "/acme/server/directory")
		if e == nil {
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("standard directory unavailable: %d", response.StatusCode)
			}
			reached = true
			break
		}
		select {
		case e := <-done:
			t.Fatalf("CA exited before handshake: %v", e)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !reached {
		t.Fatal("CA not reachable within startup observer", "elapsed", time.Since(startup), "coordinator_context", ctx.Err(), "coordinator_budget", fixtureBudget)
	}
	t.Logf("initial CA directory ready after %s; HTTP deadline remains 1s", time.Since(startup))
	response, e := client.Get("https://" + addr + "/acme/server/new-nonce")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 204 || response.Header.Get("Replay-Nonce") == "" {
		t.Fatal("runtime role cannot persist nonce", response.StatusCode)
	}
	rootData, e := os.ReadFile(filepath.Join(online, "root.pem"))
	if e != nil {
		t.Fatal(e)
	}
	rootBlock, _ := pem.Decode(rootData)
	if rootBlock == nil {
		t.Fatal("root PEM missing")
	}
	rootCert, e := x509.ParseCertificate(rootBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	statusClient := &http.Client{Timeout: time.Second}
	for path, want := range map[string]int{"/crl/root.der": 200, "/acme/server/directory": 404, "/pki/grants": 404} {
		response, e := statusClient.Get("http://" + statusAddr + path)
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || response.StatusCode != want {
			t.Fatal("status listener boundary", path, response.StatusCode, e)
		}
		if want == 200 {
			crl, e := x509.ParseRevocationList(body)
			if e != nil || crl.CheckSignatureFrom(rootCert) != nil {
				t.Fatal("public offline root CRL", e)
			}
		}
	}
	transport.CloseIdleConnections()
	stop()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	var count int
	if e := db.QueryRow(ctx, "SELECT count(*) FROM pki_issuers").Scan(&count); e != nil || count != 2 {
		t.Fatal("issuer not persisted", e, count)
	}
	connection.User = reader
	conn, e := pgx.ConnectConfig(ctx, connection)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(ctx)
	if e = conn.QueryRow(ctx, "SELECT count(*) FROM pki_issuers").Scan(&count); e != nil || count != 2 {
		t.Fatal("management cannot read public metadata", e)
	}
	for _, query := range []string{"INSERT INTO pki_serial_reservations(issuer_id,serial) SELECT id,repeat('1',40) FROM pki_issuers", "UPDATE pki_issuers SET certificate_der='replacement'::bytea", "DELETE FROM pki_issuers", "INSERT INTO pki_certificates(order_id,issuer_id,serial,der,chain,not_before,not_after) VALUES('x','x','x','x','x',now(),now())"} {
		if _, e = conn.Exec(ctx, query); e == nil {
			t.Fatal(fmt.Sprintf("management write allowed: %s", query))
		}
	}
}
