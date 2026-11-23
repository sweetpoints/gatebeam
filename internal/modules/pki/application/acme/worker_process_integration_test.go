//go:build integration

package acme_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	cert "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	management "gatebeam/internal/modules/pki/application"
	app "gatebeam/internal/modules/pki/application/acme"
	pkidomain "gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam/internal/modules/pki/infrastructure/jose"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam/internal/modules/pki/transport/acme"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// No Worker.Step, Ensure, manual compile or alternate HTTP challenge server.
// The real worker writes its webroot; bootstrap native edge serves it before
// any release can be prepared. The fixture CA speaks unmodified ACME/EAB.
func TestSeparateWorkerFirstIssueThroughBootstrapEdge(t *testing.T) {
	var listen []string
	createWorker := []string{"create"}
	if runtime.GOOS == "linux" {
		// Linux Engine does not provide Desktop's host.docker.internal mapping.
		// Bind only the owned Docker bridge, not the host's external interfaces.
		gateway := nativeCommand(t, "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", "bridge")
		if net.ParseIP(gateway) == nil {
			t.Fatal("invalid owned Docker bridge gateway", gateway)
		}
		listen = []string{net.JoinHostPort(gateway, "0")}
		createWorker = append(createWorker, "--add-host", "host.docker.internal:"+gateway)
	}
	f := newFixture(t, listen...)
	issuer := issuerForOrders(t)
	tx := postgres.NewRunner(f.db)
	if err := management.NewRegistry(tx, repo.New()).Register(t.Context(), issuer.Metadata(), issuer.Certificate.Raw); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(987), DNSNames: []string{"host.docker.internal"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, issuer.Certificate, &key.PublicKey, issuer.Signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...)
	pair, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	f.server.TLS.Certificates = []tls.Certificate{pair}
	hostURL, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://host.docker.internal:" + hostURL.Port()
	challengeURL := ""
	var validated atomic.Int64
	validate := validationFunc(func(ctx context.Context, name, token, key string) error {
		if challengeURL == "" {
			return errors.New("native challenge listener not ready")
		}
		req, err := http.NewRequestWithContext(ctx, "GET", challengeURL+"/.well-known/acme-challenge/"+token, nil)
		if err != nil {
			return err
		}
		req.Host = name
		response, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil || response.StatusCode != 200 || string(body) != key {
			return errors.New("native HTTP01 proof mismatch")
		}
		validated.Add(1)
		return nil
	})
	orders := app.NewOrders(tx, repo.New(), pkicrypto.Random{}, validate, pkicrypto.OrderSigner{Issuer: issuer}, nil)
	protocol, err := transport.NewProtocol(origin, f.service, f.nonces, josecrypto.Crypto{}, orders)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Config.Handler = protocol
	policy, _ := pkidomain.NewPolicy([]string{"host.example", "cf.example"}, pkidomain.ServerAuth)
	sealer, err := secrets.NewRecipient(f.ca.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	grants := management.NewGrantService(security{tx}, repo.New(), sealer, pkicrypto.Random{}, audit.New(), map[string]pkidomain.Policy{"server": policy}, nil)
	grant, err := grants.Authorize(t.Context(), management.ActorRef{UserID: "admin"}, management.GrantSpec{Names: []string{"host.example", "cf.example"}, Purpose: pkidomain.ServerAuth, Directory: "server", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := grants.IssueEAB(t.Context(), management.ActorRef{UserID: "admin"}, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	leafFile := filepath.Join(t.TempDir(), "leaf.agekey")
	providerFile := filepath.Join(t.TempDir(), "provider.agekey")
	for _, path := range []string{leafFile, providerFile} {
		if err = secrets.EnsureIdentity(path); err != nil {
			t.Fatal(err)
		}
	}
	leaf, err := secrets.New(leafFile)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := secrets.New(providerFile)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Chain[0].Raw})
	crypto := certcrypto.Crypto{Roots: rootPEM}
	guard := certificateSecurity{tx}
	manage := cert.NewManagement(guard, guard, certpg.New(), crypto, leaf, provider, audit.New())
	trust, err := manage.SaveTrust(t.Context(), cert.ActorRef{}, "", 0, cert.TrustBundle{Purpose: "serverAuth"}, rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	account, err := manage.SaveAccount(t.Context(), cert.ActorRef{}, "", 0, cert.ProviderAccount{Provider: "internal-server", Email: "owned@example.test", EABKeyID: binding.KeyID}, []byte(binding.HMAC))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := manage.SaveSpec(t.Context(), cert.ActorRef{}, "", 0, cert.Spec{Names: []string{"host.example", "cf.example"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01", TrustID: trust.ID, TrustRevision: trust.Revision})
	if err != nil {
		t.Fatal(err)
	}
	var currentPEM []byte
	var workerName string
	native := startPublicEdge(t, f, issuer, spec.ID, leafFile, provider.Recipient(), func(root, network, dsn, api, challenge string) {
		challengeURL = challenge
		var before int
		if err := f.db.QueryRow(t.Context(), "SELECT count(*) FROM deployment_runtime").Scan(&before); err != nil || before != 0 {
			t.Fatal("already published before first issuance", err, before)
		}
		dir := filepath.Join(root, "worker")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		providerKey, err := os.ReadFile(providerFile)
		if err != nil {
			t.Fatal(err)
		}
		cfg := bootstrap.Config{Environment: "production", Mode: "worker", DatabaseFile: "/worker/database", ManagementAPIAddress: api, CertificateProviderIdentityFile: "/worker/provider.agekey", CertificateRecipient: leaf.Recipient(), CAOrigin: origin, CertificateACMETransportTrustFile: "/worker/roots.pem", ACMEWebRoot: "/challenges"}
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"worker.json": body, "database": []byte(dsn), "provider.agekey": providerKey, "roots.pem": rootPEM} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0444); err != nil {
				t.Fatal(err)
			}
		}
		worker := network + "-worker"
		workerName = worker
		t.Cleanup(func() { nativeCommand(t, "rm", "-f", worker) })
		createArgs := append(append([]string{}, createWorker...), "--name", worker, "--network", network, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", ".5", "--pids-limit", "64", "--tmpfs", "/tmp:size=16m,mode=1777", "--tmpfs", "/var/lib/gatebeam:size=32m,uid=101,gid=101", "--mount", "type=bind,src="+dir+",dst=/worker,readonly", "--mount", "type=bind,src="+filepath.Join(root, "challenges")+",dst=/challenges", "--mount", "type=bind,src="+os.Getenv("GATEBEAM_I4_BINARY")+",dst=/gatebeam,readonly", "--entrypoint", "/gatebeam", "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "--config", "/worker/worker.json")
		nativeCommand(t, createArgs...)
		nativeCommand(t, "network", "connect", "bridge", worker)
		nativeCommand(t, "start", worker)
		until := time.Now().Add(15 * time.Second)
		for {
			err = f.db.QueryRow(t.Context(), "SELECT certificate_pem FROM certificates_versions WHERE spec_id=$1", spec.ID).Scan(&currentPEM)
			if err == nil {
				break
			}
			if time.Now().After(until) {
				t.Fatal("separate worker did not issue", nativeCommand(t, "logs", worker))
			}
			time.Sleep(100 * time.Millisecond)
		}
		nativeCommand(t, "network", "disconnect", "bridge", worker)
		if validated.Load() != 2 {
			t.Fatal("first issuance did not traverse native webroot", validated.Load())
		}
		if err := f.db.QueryRow(t.Context(), "SELECT count(*) FROM deployment_runtime").Scan(&before); err != nil || before != 0 {
			t.Fatal("issuance unexpectedly published", err, before)
		}
	})
	block, _ := pem.Decode(currentPEM)
	if block == nil {
		t.Fatal("missing issued leaf")
	}
	native.waitInitial(block.Bytes)
	native.periodicHealthDNS(workerName, block.Bytes)
	t.Log("separate production worker → shared write/read webroot → bootstrap native Nginx HTTP01 → standard EAB ACME → first verified publication/TLS/current binding PASS")
}
