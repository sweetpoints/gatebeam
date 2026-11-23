//go:build integration

package backup_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	pkidomain "gatebeam/internal/modules/pki/domain"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type certPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func makeCert(t *testing.T, parent *certPair, n int64, ca bool) certPair {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: fmt.Sprintf("owned-%d", n)}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	if ca {
		c.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		c.ExtKeyUsage = nil
	}
	signer := key
	p := c
	if parent != nil {
		signer = parent.key
		p = parent.cert
	}
	der, e := x509.CreateCertificate(rand.Reader, c, p, &key.PublicKey, signer)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return certPair{parsed, key, der}
}
func pemCert(c certPair) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}
func pemKey(t *testing.T, c certPair) []byte {
	b, e := x509.MarshalPKCS8PrivateKey(c.key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}
func crl(t *testing.T, issuer certPair, number int64, serials ...*big.Int) []byte {
	t.Helper()
	v := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
	for _, serial := range serials {
		v.RevokedCertificateEntries = append(v.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: time.Now().Add(-time.Minute), ReasonCode: 1})
	}
	der, e := x509.CreateRevocationList(rand.Reader, v, issuer.cert, issuer.key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("owned Docker fixture failed: %v %s", e, b)
	}
	return strings.TrimSpace(string(b))
}

// Native Nginx mTLS verifies the full client chain with standard CRLs only.
// There is no OCSP request or proprietary certificate-status protocol.
func nginxClient(t *testing.T, root, server, issuer, client certPair, lists []byte) int {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{"server.pem": append(pemCert(server), pemCert(root)...), "server.key": pemKey(t, server), "root.pem": pemCert(root), "crls.pem": lists, "nginx.conf": []byte("pid /tmp/nginx.pid; error_log /dev/stderr info; events {} http { access_log off; client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; server { listen 8443 ssl; ssl_certificate /fixture/server.pem; ssl_certificate_key /fixture/server.key; ssl_client_certificate /fixture/root.pem; ssl_crl /fixture/crls.pem; ssl_verify_client on; ssl_verify_depth 3; location / { return 200 'verified'; } } }")}
	for name, b := range files {
		if e := os.WriteFile(filepath.Join(dir, name), b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	name := fmt.Sprintf("gatebeam-o4-native-%d", time.Now().UnixNano())
	docker(t, "run", "-d", "--name", name, "--label", "gatebeam.o4.run="+os.Getenv("GATEBEAM_TEST_BACKUP_RUN"), "--memory", "128m", "--cpus", "1", "--pids-limit", "64", "--read-only", "--tmpfs", "/tmp:size=16m", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-v", dir+":/fixture:ro", "-p", "127.0.0.1::8443", "--entrypoint", "nginx", "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "-c", "/fixture/nginx.conf", "-g", "daemon off;")
	defer docker(t, "rm", "-f", name)
	port := strings.TrimPrefix(docker(t, "port", name, "8443/tcp"), "127.0.0.1:")
	pair, e := tls.X509KeyPair(append(pemCert(client), pemCert(issuer)...), pemKey(t, client))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	var response *http.Response
	for i := 0; i < 15; i++ {
		response, e = httpClient.Get("https://127.0.0.1:" + port + "/")
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("native CRL request unavailable", e)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != 200 {
		logs := docker(t, "logs", name)
		if !strings.Contains(logs, "certificate revoked") {
			t.Fatalf("CRL rejection was not issuer revocation: status=%d logs=%s", response.StatusCode, logs)
		}
	}
	return response.StatusCode
}
func TestPostBackupUnknownLeafRequiresIssuerWideCRLQuarantine(t *testing.T) {
	s, key, p := fixture(t)
	ctx := context.Background()
	root := makeCert(t, nil, 1, true)
	issuer := makeCert(t, &root, 2, true)
	known := makeCert(t, &issuer, 3, false)
	server := makeCert(t, &root, 4, false)
	_, e := p.Exec(ctx, `INSERT INTO pki_issuers(id,fingerprint,certificate_der,not_before,not_after) VALUES('old-issuer','fingerprint',$1,$2,$3)`, issuer.der, issuer.cert.NotBefore, issuer.cert.NotAfter)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO pki_principals VALUES('principal','{localhost}','clientAuth','client','infinity',false);INSERT INTO pki_grants(id,principal_id) VALUES('grant','principal');INSERT INTO pki_eab VALUES('binding','grant','cipher','infinity',false);INSERT INTO pki_accounts(id,principal_id,directory,thumbprint,public_key,status) VALUES('account','principal','client','thumb','key','valid')`)
	if e != nil {
		t.Fatal(e)
	}
	insert := func(c certPair, id string) {
		t.Helper()
		serial := fmt.Sprintf("%040x", c.cert.SerialNumber)
		_, e := p.Exec(ctx, `INSERT INTO pki_serial_reservations(issuer_id,serial) VALUES('old-issuer',$1)`, serial)
		if e != nil {
			t.Fatal(e)
		}
		_, e = p.Exec(ctx, `INSERT INTO pki_orders(id,account_id,directory,names,purpose,status,expires,challenges,revision) VALUES($1,'account','client','{localhost}','clientAuth','valid','infinity','[]',1)`, id)
		if e != nil {
			t.Fatal(e)
		}
		_, e = p.Exec(ctx, `INSERT INTO pki_certificates VALUES($2,'old-issuer',$1,$3,$4,$5,$6)`, serial, id, c.der, pemCert(issuer), c.cert.NotBefore, c.cert.NotAfter)
		if e != nil {
			t.Fatal(e)
		}
	}
	insert(known, "known")
	a := create(t, s)
	// Certificate is signed and committed only after this immutable backup.
	unknown := makeCert(t, &issuer, 5, false)
	insert(unknown, "post-backup")
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	r := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	report, e := r.Verify(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Restore(ctx, report, application.Conservative); e != nil {
		t.Fatal(e)
	}
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = target.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	defer p.Exec(ctx, `DROP DATABASE `+target.Database+` WITH (FORCE)`)
	repo := pkipg.New()
	runner := platform.NewRunner(restored)
	e = runner.Within(ctx, func(sc transaction.Scope) error {
		good, e := repo.Status(sc, "old-issuer", pkidomain.Serial(fmt.Sprintf("%040x", known.cert.SerialNumber)))
		if e != nil || good.State != pkidomain.StatusRevoked {
			t.Fatal("known cert not revoked", e)
		}
		missing, e := repo.Status(sc, "old-issuer", pkidomain.Serial(fmt.Sprintf("%040x", unknown.cert.SerialNumber)))
		if e != nil || missing.State != pkidomain.StatusUnknown {
			t.Fatal("postbackup certificate not unknown", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var disabled, consumed, deactivated, quarantined bool
	restored.QueryRow(ctx, `SELECT (SELECT disabled FROM pki_principals LIMIT 1),(SELECT consumed FROM pki_eab LIMIT 1),(SELECT status='deactivated' FROM pki_accounts LIMIT 1),EXISTS(SELECT 1 FROM pki_restore_quarantine)`).Scan(&disabled, &consumed, &deactivated, &quarantined)
	if !disabled || !consumed || !deactivated || !quarantined {
		t.Fatal("PKI recovery reactivated old authority")
	}
	e = runner.Within(ctx, func(sc transaction.Scope) error {
		return repo.Register(sc, pkidomain.Issuer{ID: "old-issuer", Fingerprint: "fingerprint", NotBefore: issuer.cert.NotBefore, NotAfter: issuer.cert.NotAfter}, issuer.der)
	})
	if e == nil {
		t.Fatal("quarantined issuer can restart")
	}
	// Demonstrate why merely revoking all known leaves is unsafe for CRL-only
	// peers, then execute the offline-root prerequisite for allowed retrust.
	stale := append(crl(t, issuer, 2, known.cert.SerialNumber), crl(t, root, 1)...)
	if got := nginxClient(t, root, server, issuer, unknown, stale); got != 200 {
		t.Fatalf("unknown postbackup leaf baseline=%d", got)
	}
	revoked := append(crl(t, issuer, 3, known.cert.SerialNumber), crl(t, root, 2, issuer.cert.SerialNumber)...)
	if got := nginxClient(t, root, server, issuer, unknown, revoked); got != 400 {
		t.Fatal("unknown postbackup leaf survived issuer-wide root CRL")
	}
	replacement := makeCert(t, &root, 6, true)
	fresh := makeCert(t, &replacement, 7, false)
	rotated := append(revoked, crl(t, replacement, 1)...)
	if got := nginxClient(t, root, server, replacement, fresh, rotated); got != 200 {
		t.Fatalf("fresh replacement trust failed=%d", got)
	}
}
