//go:build integration

package composition

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"gatebeam/internal/integration/certificateaccess"
	"gatebeam/internal/modules/certificates"
	certapp "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/modules/pki"
	pkiapp "gatebeam/internal/modules/pki/application"
	acmeapp "gatebeam/internal/modules/pki/application/acme"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam/internal/modules/pki/infrastructure/jose"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	acmeHTTP "gatebeam/internal/modules/pki/transport/acme"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type webHTTP01 struct{ server *httptest.Server }

func (v webHTTP01) Validate(ctx context.Context, name, token, key string) error {
	req, e := http.NewRequestWithContext(ctx, "GET", v.server.URL+"/.well-known/acme-challenge/"+token, nil)
	if e != nil {
		return e
	}
	res, e := v.server.Client().Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 4096))
	if e != nil || res.StatusCode != 200 || string(b) != key {
		return errors.New("owned HTTP01 challenge rejected")
	}
	return nil
}

// webPKI hosts an owned standard CA and a separate ordinary lego worker.
// Only a fresh age public recipient enters the API's enrollment assembly.
func webPKI(t *testing.T, p *pgxpool.Pool) (bootstrap.Config, map[string]any) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	offline, online := filepath.Join(dir, "offline"), filepath.Join(dir, "online")
	if e := pki.BootstrapOffline(ctx, pkiapp.BootstrapCommand{RootDirectory: offline, OnlineDirectory: online, RootName: "browser owned root", IntermediateName: "browser owned issuer", StatusOrigin: "http://status.owned.test"}); e != nil {
		t.Fatal(e)
	}
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: filepath.Join(online, "identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	if e = pki.RegisterIssuer(ctx, p, issuer); e != nil {
		t.Fatal(e)
	}
	caSecret, e := secrets.New(filepath.Join(online, "identity.agekey"))
	if e != nil {
		t.Fatal(e)
	}
	leafFile, providerFile := filepath.Join(dir, "leaf"), filepath.Join(dir, "provider")
	for _, path := range []string{leafFile, providerFile} {
		if e = secrets.EnsureIdentity(path); e != nil {
			t.Fatal(e)
		}
	}
	leaf, _ := secrets.New(leafFile)
	provider, _ := secrets.New(providerFile)
	webroot := filepath.Join(dir, "webroot")
	if e = os.MkdirAll(webroot, 0700); e != nil {
		t.Fatal(e)
	}
	challenge := httptest.NewServer(http.FileServer(http.Dir(webroot)))
	t.Cleanup(challenge.Close)
	ca := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ca.Close)
	tx := postgres.NewRunner(p)
	repo := pkipg.New()
	orders := acmeapp.NewOrders(tx, repo, pkicrypto.Random{}, webHTTP01{challenge}, pkicrypto.OrderSigner{Issuer: issuer}, nil)
	protocol, e := acmeHTTP.NewProtocol(ca.URL, acmeapp.New(tx, repo, pkicrypto.Random{}, caSecret, nil), acmeapp.NewNonces(tx, repo, pkicrypto.Random{}, nil), josecrypto.Crypto{}, orders)
	if e != nil {
		t.Fatal(e)
	}
	ca.Config.Handler = protocol
	transportFile := filepath.Join(dir, "transport.pem")
	if e = os.WriteFile(transportFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	worker, e := certificates.NewWorker(p, certificateaccess.Graph{Ingress: ingress.New(p, nil)}, providerFile, leaf.Recipient(), webroot, certificates.InternalACME{Origin: ca.URL, TransportTrustFile: transportFile})
	if e != nil {
		t.Fatal(e)
	}
	command, result := filepath.Join(dir, "command"), filepath.Join(dir, "result")
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				in, ok := consumeWebPKICommand(command)
				if !ok {
					continue
				}
				c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				var err error
				var v certapp.Version
				switch in.Action {
				case "mfa":
					_, err = p.Exec(c, "UPDATE identity_accounts SET last_step=-1 WHERE name='browser-admin'")
				case "prepare":
					err = worker.PrepareCurrent(c)
				case "renew":
					v, err = worker.Renew(c, in.ID)
				case "fail":
					ca.Close()
					if in.Revision > 0 {
						_, err = worker.RenewRevision(c, in.ID, in.Revision)
					} else {
						_, err = worker.Renew(c, in.ID)
					}
				}
				cancel()
				out, _ := json.Marshal(map[string]any{"action": in.Action, "request": in.Request, "failed": err != nil, "version_id": v.ID})
				if e := os.WriteFile(result, out, 0600); e != nil {
					t.Error("owned worker result write failed")
				}
			}
		}
	}()
	root, e := os.ReadFile(filepath.Join(online, "root.pem"))
	if e != nil {
		t.Fatal(e)
	}
	return bootstrap.Config{CARecipient: caSecret.Recipient(), CAServerNames: []string{"entry.owned.test"}, CAClientNames: []string{"client.owned.test"}, CAOrigin: ca.URL, CertificateRecipient: leaf.Recipient(), CertificateProviderRecipient: provider.Recipient()}, map[string]any{"workerCommand": command, "workerResult": result, "trustPEM": string(root), "_leafIdentityPath": leafFile, "_providerRecipient": provider.Recipient()}
}

type webPKICommand struct {
	Action, ID string
	Request    int
	Revision   int64
}

// The browser writes this owned fixture file from another process. A reader
// can see an empty or partial write; remove only a completely decoded command.
func consumeWebPKICommand(path string) (webPKICommand, bool) {
	var command webPKICommand
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &command) != nil {
		return command, false
	}
	if os.Remove(path) != nil {
		return command, false
	}
	return command, true
}
