//go:build integration

package main

import (
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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/testkit"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ocsp"
)

func TestStandaloneCA(t *testing.T) {
	db := testkit.Postgres(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := postgres.MigrateRoles(ctx, db); err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse(os.Getenv("GATEBEAM_CA_TEST_DATABASE_URL"))
	if err != nil || base.Scheme == "" {
		t.Fatal("test database URL syntax is required")
	}
	params := base.Query()
	schema := db.Config().ConnConfig.RuntimeParams["search_path"]
	params.Set("search_path", schema)
	base.RawQuery = params.Encode()

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	login := func(suffix, role string) string {
		t.Helper()
		name := pgx.Identifier{schema + "_" + suffix}.Sanitize()
		if _, err := db.Exec(ctx, "CREATE ROLE "+name+" LOGIN PASSWORD 'owned-fixture-only'"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := db.Exec(context.Background(), "DROP ROLE "+name); err != nil {
				t.Error(err)
			}
		})
		if _, err := db.Exec(ctx, "GRANT "+role+" TO "+name); err != nil {
			t.Fatal(err)
		}
		u := *base
		u.User = url.UserPassword(schema+"_"+suffix, "owned-fixture-only")
		return write(suffix+".dsn", []byte(u.String()))
	}
	addr, statusAddr := unusedAddress(t), unusedAddress(t)
	if addr == statusAddr {
		statusAddr = unusedAddress(t)
	}
	c := config{
		DatabaseFile: login("runtime", "gatebeam_ca_runtime"),
		Listen:       addr, Origin: "https://" + addr,
		StatusListen: statusAddr, StatusOrigin: "http://" + statusAddr,
		ServerNames: []string{"fixture.internal.test"}, ClientNames: []string{"client.internal.test"},
		ValidationNetworks: []string{"10.23.3.0/24"},
	}
	offline := filepath.Join(dir, "offline")
	online := filepath.Join(dir, "online")
	if err := run(ctx, []string{"bootstrap", "-offline", offline, "-online", online,
		"-root-name", "Fixture root", "-issuer-name", "Fixture issuer", "-status-origin", c.StatusOrigin}, io.Discard); err != nil {
		t.Fatal(err)
	}
	c.IssuerFile = filepath.Join(online, "issuer.pem")
	c.RootFile = filepath.Join(online, "root.pem")
	c.SignerFile = filepath.Join(online, "issuer.age")
	c.IdentityFile = filepath.Join(online, "identity.agekey")
	c.RootCRLFile = filepath.Join(online, "root.crl.der")
	c.RootOCSPCertificateFile = filepath.Join(online, "root-ocsp.pem")
	c.RootOCSPSignerFile = filepath.Join(online, "root-ocsp.age")

	root := readCert(t, c.RootFile)
	keyPEM, err := os.ReadFile(filepath.Join(offline, "root-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	signer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	transportKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "CA transport fixture"}, SerialNumber: big.NewInt(2),
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &transportKey.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(transportKey)
	if err != nil {
		t.Fatal(err)
	}
	c.TLSCertificateFile = write("transport.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	c.TLSKeyFile = write("transport-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	encodeConfig := func(name string, c config) string {
		t.Helper()
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, data)
	}
	servePath := encodeConfig("serve.json", c)
	recipient, err := os.ReadFile(filepath.Join(online, "recipient.txt"))
	if err != nil {
		t.Fatal(err)
	}
	admin := config{
		DatabaseFile: login("admin", "gatebeam_ca_admin"), Origin: c.Origin,
		Recipient: strings.TrimSpace(string(recipient)), ServerNames: c.ServerNames, ClientNames: c.ClientNames,
	}
	adminPath := encodeConfig("admin.json", admin)
	var response bytes.Buffer
	authorize := []string{"authorize", "-config", adminPath, "-directory", "server", "-names", c.ServerNames[0],
		"-expires", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := run(ctx, authorize, &response); err != nil {
		t.Fatal("authorize:", err)
	}
	var grant application.Grant
	if err := json.NewDecoder(&response).Decode(&grant); err != nil || grant.ID == "" {
		t.Fatal("missing grant", err)
	}
	eabPath := filepath.Join(dir, "eab.json")
	if err := run(ctx, []string{"issue-eab", "-config", adminPath, "-grant", grant.ID, "-output", eabPath}, io.Discard); err != nil {
		t.Fatal("issue EAB:", err)
	}
	if err := run(ctx, []string{"inspect", "-config", servePath}, io.Discard); err == nil {
		t.Fatal("runtime login acquired administration access")
	}
	auditActors := 0
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit WHERE actor_id=$1", schema+"_admin").Scan(&auditActors); err != nil || auditActors != 2 {
		t.Fatal("management audit missing", err)
	}

	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "-config", servePath}, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("CA service:", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("CA did not shut down")
		}
	})
	trust := x509.NewCertPool()
	trust.AddCert(root)
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12}},
	}
	defer client.CloseIdleConnections()
	directory := c.Origin + "/acme/server/directory"
	for range 100 {
		r, err := client.Get(directory)
		if err == nil {
			r.Body.Close()
			if r.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	eabFile, err := os.Open(eabPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eabFile.Close()
	var binding application.EABCredentials
	if err := json.NewDecoder(eabFile).Decode(&binding); err != nil {
		t.Fatal(err)
	}
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lego, err := api.New(client, "gatebeam-ca-test", directory, "", accountKey)
	if err != nil {
		t.Fatal("Lego directory:", err)
	}
	if _, err := lego.Accounts.NewEAB(ctx, legoacme.Account{TermsOfServiceAgreed: true}, binding.KeyID, binding.HMAC); err != nil {
		t.Fatal("Lego EAB registration:", err)
	}
	if err := run(ctx, []string{"inspect", "-config", adminPath}, io.Discard); err != nil {
		t.Fatal("inspect:", err)
	}
	issuer := readCert(t, c.IssuerFile)
	ocspRequest, err := ocsp.CreateRequest(issuer, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	statusClient := &http.Client{Timeout: 2 * time.Second}
	r, err := statusClient.Post(c.StatusOrigin+"/ocsp", "application/ocsp-request", bytes.NewReader(ocspRequest))
	body := readResponse(t, r, err)
	status, err := ocsp.ParseResponseForCert(body, issuer, root)
	if err != nil || status.Status != ocsp.Good {
		t.Fatal("invalid OCSP result:", err)
	}
	r, err = statusClient.Get(c.StatusOrigin + "/crl/root.der")
	crl, err := x509.ParseRevocationList(readResponse(t, r, err))
	if err != nil || crl.CheckSignatureFrom(root) != nil {
		t.Fatal("invalid root CRL:", err)
	}
}

func unusedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	return addr
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("missing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func readResponse(t *testing.T, r *http.Response, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status:", r.Status)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
