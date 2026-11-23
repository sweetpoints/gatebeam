//go:build integration

package composition

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/modules/pki"
	management "gatebeam/internal/modules/pki/application"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	fixture "gatebeam/tests/fixtures/deployment"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAReadinessSurvivesPeerLoss(t *testing.T) {
	pool := testkit.Postgres(t)
	roles := fixture.RuntimeRoles(t, pool)
	directory, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	online := filepath.Join(directory, "online")
	if e = (pkicrypto.Bootstrapper{}).Generate(t.Context(), management.BootstrapCommand{RootDirectory: filepath.Join(directory, "offline"), OnlineDirectory: online, RootName: "HA role fixture root", IntermediateName: "HA role fixture issuer", StatusOrigin: "http://status.ha.internal.test"}); e != nil {
		t.Fatal(e)
	}
	identityA, identityB := filepath.Join(online, "identity.agekey"), filepath.Join(directory, "ca-b.agekey")
	if e = secrets.EnsureIdentity(identityB); e != nil {
		t.Fatal(e)
	}
	a, e := secrets.New(identityA)
	if e != nil {
		t.Fatal(e)
	}
	b, e := secrets.New(identityB)
	if e != nil {
		t.Fatal(e)
	}
	public := []string{a.Recipient(), b.Recipient()}
	issuerConfig := pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: identityA}
	if e = pki.RewrapOnlineSigners(t.Context(), issuerConfig, filepath.Join(online, "root-ocsp.age"), public); e != nil {
		t.Fatal(e)
	}
	issuer, e := pkicrypto.LoadIssuer(issuerConfig)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	der, e := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2026), DNSNames: []string{"ca.ha.internal.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, issuer.Certificate, &key.PublicKey, issuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	certificatePath, keyPath := filepath.Join(directory, "transport.pem"), filepath.Join(directory, "transport.key")
	certificate := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate.Raw})...)
	if e = os.WriteFile(certificatePath, certificate, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); e != nil {
		t.Fatal(e)
	}
	reserve := func() string {
		t.Helper()
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	type instance struct {
		cancel  context.CancelFunc
		done    chan error
		health  string
		stopped bool
	}
	instances := make([]instance, 2)
	for i, identity := range []string{identityA, identityB} {
		dsn, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
		if e != nil {
			t.Fatal(e)
		}
		dsn.User = url.UserPassword(roles["ca"].Name, roles["ca"].Password)
		parameters := dsn.Query()
		parameters.Set("search_path", pool.Config().ConnConfig.RuntimeParams["search_path"])
		dsn.RawQuery = parameters.Encode()
		database := filepath.Join(directory, fmt.Sprintf("database-%d", i))
		if e = os.WriteFile(database, []byte(dsn.String()), 0600); e != nil {
			t.Fatal(e)
		}
		cfg := bootstrap.Config{Mode: "ca", Environment: "development", RuntimeProtocol: 1, NodeID: []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}[i], NodeEpoch: 1, DatabaseFile: database, CAIdentityFile: identity, CAListen: reserve(), CAStatusListen: reserve(), CAHostname: "ca.ha.internal.test", CAOrigin: "https://ca.ha.internal.test", CATLSCertificateFile: certificatePath, CATLSKeyFile: keyPath, CACertificateFile: issuerConfig.CertificateFile, CARootFile: issuerConfig.RootFile, CASignerFile: issuerConfig.SignerFile, CARootOCSPCertificateFile: filepath.Join(online, "root-ocsp.pem"), CARootOCSPSignerFile: filepath.Join(online, "root-ocsp.age"), CARootCRLFile: filepath.Join(online, "root.crl.der"), CAStatusOrigin: "http://status.ha.internal.test", CAServerNames: []string{"service.ha.internal.test"}, CAClientNames: []string{"client.ha.internal.test"}, CAValidationNetworks: []string{"10.0.0.0/8"}, HealthListen: reserve(), DrainSeconds: 1, EncryptionRecipients: secrets.RolePolicy{"ca": public}}
		own, e := secrets.New(identity)
		if e != nil {
			t.Fatal(e)
		}
		registration, _ := json.Marshal(map[string]any{"EncryptionRecipients": map[string]string{"ca": own.Recipient()}})
		if _, e = pool.Exec(t.Context(), `INSERT INTO deployment_nodes(id,epoch,principal,registration) VALUES($1,1,$2,$3)`, cfg.NodeID, "owned_edge_"+fmt.Sprint(i), registration); e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		instances[i] = instance{cancel: cancel, done: done, health: cfg.HealthListen}
		go func() { done <- Run(ctx, "ca", cfg) }()
	}
	defer func() {
		for i := range instances {
			instance := &instances[i]
			if !instance.stopped {
				instance.cancel()
				select {
				case e := <-instance.done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(3 * time.Second):
					t.Error("CA drain exceeded deadline")
				}
			}
		}
	}()
	client := &http.Client{Timeout: time.Second}
	wait := func(index int, path string, want int) {
		t.Helper()
		deadline := time.NewTimer(8 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case e := <-instances[index].done:
				instances[index].stopped = true
				t.Fatalf("CA %d exited before ready: %v", index, e)
			case <-deadline.C:
				t.Fatalf("CA %d %s not ready", index, path)
			case <-tick.C:
				response, e := client.Get("http://" + instances[index].health + path)
				if e == nil {
					_, _ = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode == want {
						return
					}
				}
			}
		}
	}
	for i := range instances {
		wait(i, "/readyz/acme", 200)
		wait(i, "/readyz/status", 200)
	}
	instances[0].cancel()
	select {
	case e := <-instances[0].done:
		instances[0].stopped = true
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CA A did not stop")
	}
	wait(1, "/livez", 200)
	wait(1, "/readyz/acme", 200)
	wait(1, "/readyz/status", 200)
}
