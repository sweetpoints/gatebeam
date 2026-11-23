//go:build integration

package acme_test

import (
	"context"
	"encoding/pem"
	"errors"
	"gatebeam/internal/integration/certificatematerials"
	cert "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certlego "gatebeam/internal/modules/certificates/infrastructure/lego"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	deploymentdomain "gatebeam/internal/modules/deployment/domain"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	management "gatebeam/internal/modules/pki/application"
	app "gatebeam/internal/modules/pki/application/acme"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam/internal/modules/pki/infrastructure/jose"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam/internal/modules/pki/transport/acme"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type certificateSecurity struct{ tx transaction.Runner }

func (s certificateSecurity) Within(ctx context.Context, _ cert.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}
func (certificateSecurity) RequireWithin(transaction.Scope, cert.ActorRef, []string) error {
	return nil
}
func (certificateSecurity) GuardWithin(transaction.Scope) error { return nil }
func TestPublicClientStandardEABRenewalAndFailurePreservesVersion(t *testing.T) {
	f := newFixture(t)
	issuer := issuerForOrders(t)
	tx := postgres.NewRunner(f.db)
	if e := management.NewRegistry(tx, repo.New()).Register(context.Background(), issuer.Metadata(), issuer.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	web := t.TempDir()
	http01 := httptest.NewServer(http.FileServer(http.Dir(web)))
	defer http01.Close()
	validate := validationFunc(func(ctx context.Context, name, token, key string) error {
		req, e := http.NewRequestWithContext(ctx, "GET", http01.URL+"/.well-known/acme-challenge/"+token, nil)
		if e != nil {
			return e
		}
		response, e := http01.Client().Do(req)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 4096))
		if e != nil || response.StatusCode != 200 || string(body) != key {
			return errors.New("HTTP01 proof mismatch")
		}
		return nil
	})
	orders := app.NewOrders(tx, repo.New(), pkicrypto.Random{}, validate, pkicrypto.OrderSigner{Issuer: issuer}, nil)
	protocol, e := transport.NewProtocol(f.server.URL, f.service, f.nonces, josecrypto.Crypto{}, orders)
	if e != nil {
		t.Fatal(e)
	}
	f.server.Config.Handler = protocol
	_, binding := f.grant("server")
	identity := filepath.Join(t.TempDir(), "materials.agekey")
	if e = secrets.EnsureIdentity(identity); e != nil {
		t.Fatal(e)
	}
	secret, e := secrets.New(identity)
	if e != nil {
		t.Fatal(e)
	}
	providerIdentity := filepath.Join(t.TempDir(), "providers.agekey")
	if e = secrets.EnsureIdentity(providerIdentity); e != nil {
		t.Fatal(e)
	}
	providerSecrets, e := secrets.New(providerIdentity)
	if e != nil {
		t.Fatal(e)
	}
	crypto := certcrypto.Crypto{Roots: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Chain[len(issuer.Chain)-1].Raw})}
	guard := certificateSecurity{tx}
	store := certpg.New()
	manage := cert.NewManagement(guard, guard, store, crypto, secret, providerSecrets, audit.New())
	account, e := manage.SaveAccount(context.Background(), cert.ActorRef{}, "", 0, cert.ProviderAccount{Provider: "google", Email: "owned@example.test", EABKeyID: binding.KeyID}, []byte(binding.HMAC))
	if e != nil {
		t.Fatal(e)
	}
	spec, e := manage.SaveSpec(context.Background(), cert.ActorRef{}, "", 0, cert.Spec{Names: []string{"host.example"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"})
	if e != nil {
		t.Fatal(e)
	}
	client := &certlego.Client{Secrets: providerSecrets, WebRoot: web, HTTPClient: f.server.Client(), Directories: map[string]string{"google": f.server.URL + "/acme/server/directory"}}
	service := cert.New(tx, store, guard, crypto, secret, client, jobs.New(f.db))
	worker := certificatematerials.Worker{Published: deploymentpg.NewRuntime(f.db, jobs.New(f.db), nil), Certificates: service}
	if e = worker.Step(context.Background()); e != nil && !errors.Is(e, deploymentdomain.ErrNotFound) {
		t.Fatal("initial worker preparation", e)
	}
	var first cert.Version
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error { v, e := store.Current(sc, spec.ID, 1); first = v.Version; return e }); e != nil {
		t.Fatal("worker did not prepare first certificate before publication", e)
	}
	readLeaf := func() []byte {
		var raw []byte
		if e := tx.Within(context.Background(), func(sc transaction.Scope) error {
			v, e := store.Current(sc, spec.ID, 1)
			if e == nil {
				block, _ := pem.Decode(v.CertificatePEM)
				raw = block.Bytes
			}
			return e
		}); e != nil {
			t.Fatal(e)
		}
		return raw
	}
	native := startPublicEdge(t, f, issuer, spec.ID, identity, providerSecrets.Recipient())
	native.waitInitial(readLeaf())
	native.revokePublisher()
	next, e := service.Renew(context.Background(), spec.ID)
	if e != nil || next.ID == first.ID || next.Digest == first.Digest {
		t.Fatal("standard renewal", e)
	}
	native.wait(readLeaf())
	f.server.Close()
	if _, e = service.Renew(context.Background(), spec.ID); e == nil {
		t.Fatal("offline CA accepted")
	}
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error {
		current, e := store.Current(sc, spec.ID, 1)
		if e == nil && (current.ID != next.ID || !current.Usable(time.Now())) {
			return errors.New("valid material changed on failure")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	t.Log("worker pre-publication standard EAB/HTTP01 issue + publisher session revoked + renew + real edge ApplyDerived serves new TLS certificate without publishing unrelated draft + CA outage retains immutable last-valid material PASS")
}
