//go:build integration

package pki_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"gatebeam/internal/modules/pki"
	management "gatebeam/internal/modules/pki/application"
	app "gatebeam/internal/modules/pki/application/acme"
	statusapp "gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam/internal/modules/pki/infrastructure/jose"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam/internal/modules/pki/transport/acme"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/registration"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dualCASecurity struct{ tx transaction.Runner }

func (s dualCASecurity) Within(ctx context.Context, _ management.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}

type dualCAUser struct {
	key     crypto.Signer
	account *legoacme.ExtendedAccount
}

func (u *dualCAUser) GetEmail() string                           { return "ha@example.test" }
func (u *dualCAUser) GetPrivateKey() crypto.Signer               { return u.key }
func (u *dualCAUser) GetRegistration() *legoacme.ExtendedAccount { return u.account }

type dualValidation func(context.Context, string, string, string) error

func (v dualValidation) Validate(ctx context.Context, n, t, k string) error { return v(ctx, n, t, k) }

type dualCAFixture struct {
	online, identityA string
	pools             [2]*pgxpool.Pool
	issuer            pkicrypto.Issuer
	identities        [2]*secrets.Store
	grants            *management.GrantService
	server            *httptest.Server
	handlers          [2]http.Handler
	orders            [2]*app.OrderService
	statuses          [2]*statusapp.Service
	current           atomic.Int32
}

func newDualCAFixture(t *testing.T) *dualCAFixture {
	t.Helper()
	p := testkit.Postgres(t)
	peer, e := pgxpool.NewWithConfig(t.Context(), p.Config().Copy())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(peer.Close)
	f := &dualCAFixture{pools: [2]*pgxpool.Pool{p, peer}}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	online := filepath.Join(dir, "online")
	command := management.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: online, RootName: "owned HA root", IntermediateName: "owned HA issuer", StatusOrigin: "http://status.ha.internal.test"}
	if e = (pkicrypto.Bootstrapper{}).Generate(t.Context(), command); e != nil {
		t.Fatal(e)
	}
	identityA, identityB := filepath.Join(online, "identity.agekey"), filepath.Join(dir, "ca-b.agekey")
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
	a, e = secrets.NewRoleStore(identityA, public)
	if e != nil {
		t.Fatal(e)
	}
	b, e = secrets.NewRoleStore(identityB, public)
	if e != nil {
		t.Fatal(e)
	}
	f.identities = [2]*secrets.Store{a, b}
	f.online = online
	f.identityA = identityA
	issuerConfig := pkicrypto.Config{CertificateFile: filepath.Join(online, "issuer.pem"), RootFile: filepath.Join(online, "root.pem"), SignerFile: filepath.Join(online, "issuer.age"), IdentityFile: identityA}
	if e = pki.RewrapOnlineSigners(t.Context(), issuerConfig, filepath.Join(online, "root-ocsp.age"), public); e != nil {
		t.Fatal(e)
	}
	f.issuer, e = pkicrypto.LoadIssuer(issuerConfig)
	if e != nil {
		t.Fatal(e)
	}
	issuerConfig.IdentityFile = identityB
	other, e := pkicrypto.LoadIssuer(issuerConfig)
	if e != nil || !bytes.Equal(other.Certificate.Raw, f.issuer.Certificate.Raw) {
		t.Fatal("independent CA B could not load shared logical issuer", e)
	}
	if e = management.NewRegistry(postgres.NewRunner(p), repo.New()).Register(t.Context(), f.issuer.Metadata(), f.issuer.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	sealer, e := secrets.NewRecipients(public)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := domain.NewPolicy([]string{"ha.internal.test"}, domain.ServerAuth)
	if e != nil {
		t.Fatal(e)
	}
	f.grants = management.NewGrantService(dualCASecurity{postgres.NewRunner(p)}, repo.New(), sealer, pkicrypto.Random{}, audit.New(), map[string]domain.Policy{"server": policy}, nil)
	// The logical TLS entry routes alternate requests to independent protocol
	// instances. It retains the canonical ACME URLs while an instance disappears.
	var requests atomic.Uint64
	f.current.Store(-1)
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := f.current.Load()
		if index < 0 {
			index = int32(requests.Add(1) % 2)
		}
		f.handlers[index].ServeHTTP(w, r)
	}))
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	validator := dualValidation(func(ctx context.Context, name, token, keyAuthorization string) error {
		challenge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/acme-challenge/"+token {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, keyAuthorization)
		}))
		defer challenge.Close()
		request, e := http.NewRequestWithContext(ctx, "GET", challenge.URL+"/.well-known/acme-challenge/"+token, nil)
		if e != nil {
			return e
		}
		request.Host = name
		response, e := challenge.Client().Do(request)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		body, e := io.ReadAll(response.Body)
		if e != nil || response.StatusCode != 200 || string(body) != keyAuthorization {
			return errors.New("owned HTTP01 proof failed")
		}
		return nil
	})
	for i, pool := range f.pools {
		signer := app.Signer(pkicrypto.OrderSigner{Issuer: f.issuer})
		tx := postgres.NewRunner(pool)
		f.orders[i] = app.NewOrders(tx, repo.New(), pkicrypto.Random{}, validator, signer, nil)
		accounts := app.New(tx, repo.New(), pkicrypto.Random{}, f.identities[i], nil)
		nonces := app.NewNonces(tx, repo.New(), pkicrypto.Random{}, nil)
		f.handlers[i], e = transport.NewProtocol(f.server.URL, accounts, nonces, josecrypto.Crypto{}, f.orders[i])
		if e != nil {
			t.Fatal(e)
		}
		f.statuses[i] = statusapp.New(tx, repo.New(), pkicrypto.NewStatusSigner(f.issuer), nil)
	}
	return f
}
func (f *dualCAFixture) client(t *testing.T) (*api.Core, app.AccountRef) {
	t.Helper()
	grant, e := f.grants.Authorize(t.Context(), management.ActorRef{UserID: "ha-admin"}, management.GrantSpec{Names: []string{"ha.internal.test"}, Purpose: domain.ServerAuth, Directory: "server", Expires: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	binding, e := f.grants.IssueEAB(t.Context(), management.ActorRef{UserID: "ha-admin"}, grant.ID)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	user := &dualCAUser{key: key}
	core, e := api.New(f.server.Client(), "gatebeam-owned-ha", f.server.URL+"/acme/server/directory", "", key)
	if e != nil {
		t.Fatal(e)
	}
	user.account, e = registration.NewRegistrar(core, user).RegisterWithExternalAccountBinding(t.Context(), registration.RegisterEABOptions{Kid: binding.KeyID, HmacEncoded: binding.HMAC, TermsOfServiceAgreed: true})
	if e != nil {
		t.Fatal(e)
	}
	core, e = api.New(f.server.Client(), "gatebeam-owned-ha", f.server.URL+"/acme/server/directory", user.account.Location, key)
	if e != nil {
		t.Fatal(e)
	}
	// Read the protected account thumbprint to drive only the focused concurrent
	// owner test; all account/order/challenge wire operations still use Lego.
	id := strings.TrimPrefix(user.account.Location, f.server.URL+"/acme/server/account/")
	var thumbprint string
	if e = f.pools[0].QueryRow(t.Context(), `SELECT thumbprint FROM pki_accounts WHERE id=$1`, id).Scan(&thumbprint); e != nil {
		t.Fatal(e)
	}
	return core, app.AccountRef{Directory: "server", ID: id, Thumbprint: thumbprint}
}
func dualCSR(t *testing.T) []byte {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"ha.internal.test"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	return csr
}
func (f *dualCAFixture) ready(t *testing.T, core *api.Core) legoacme.ExtendedOrder {
	t.Helper()
	order, e := core.Orders.New(t.Context(), []string{"ha.internal.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, authorizationURL := range order.Authorizations {
		authorization, e := core.Authorizations.Get(t.Context(), authorizationURL)
		if e != nil {
			t.Fatal(e)
		}
		if len(authorization.Challenges) != 1 {
			t.Fatal("standard HTTP01 missing")
		}
		if _, e = core.Challenges.New(t.Context(), authorization.Challenges[0].URL); e != nil {
			t.Fatal(e)
		}
	}
	ready, e := core.Orders.Get(t.Context(), order.Location)
	if e != nil || ready.Status != "ready" {
		t.Fatal("order not ready across instances", ready.Status, e)
	}
	return order
}
func TestACMEOrderSurvivesInstanceLoss(t *testing.T) {
	f := newDualCAFixture(t)
	core, ref := f.client(t)
	order := f.ready(t, core)
	csr := dualCSR(t)
	childDirectory := t.TempDir()
	database := filepath.Join(childDirectory, "database")
	dsn, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	parameters := dsn.Query()
	parameters.Set("search_path", f.pools[0].Config().ConnConfig.RuntimeParams["search_path"])
	dsn.RawQuery = parameters.Encode()
	if e = os.WriteFile(database, []byte(dsn.String()), 0600); e != nil {
		t.Fatal(e)
	}
	command := caCrashCommand{Database: database, Online: f.online, Identity: f.identityA, Ref: ref, OrderID: strings.TrimPrefix(order.Location, f.server.URL+"/acme/server/order/"), CSR: csr}
	body, _ := json.Marshal(command)
	path := filepath.Join(childDirectory, "crash-command.json")
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	childCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestCAFinalizeCrashChild$")
	child.Env = append(os.Environ(), "GATEBEAM_CA_CRASH_CHILD="+path)
	output, e := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("CA did not exit exactly after real signing: %v %s", e, output)
	}
	f.current.Store(1)
	result, e := core.Orders.UpdateForCSR(t.Context(), order.Finalize, csr)
	if e != nil || result.Status != "valid" {
		t.Fatal("B failed to resume existing standard order", result.Status, e)
	}
	certificate, e := core.Certificates.Get(t.Context(), result.Certificate, true)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(certificate.Cert)
	if block == nil {
		t.Fatal("standard PEM chain missing")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil || leaf.VerifyHostname("ha.internal.test") != nil {
		t.Fatal("recovered leaf invalid", e)
	}
	var certificates, serials int
	if e = f.pools[0].QueryRow(t.Context(), `SELECT count(*) FROM pki_certificates`).Scan(&certificates); e != nil || certificates != 1 {
		t.Fatal("lost-signature retry duplicated certificate", certificates, e)
	}
	if e = f.pools[0].QueryRow(t.Context(), `SELECT count(*) FROM pki_serial_reservations`).Scan(&serials); e != nil || serials != 1 {
		t.Fatal("rolled-back signature leaked serial reservation", serials, e)
	}
	again, e := core.Orders.UpdateForCSR(t.Context(), order.Finalize, csr)
	if e != nil || again.Certificate != result.Certificate {
		t.Fatal("committed finalize was not idempotent", e)
	}
}
func TestConcurrentFinalizeAndCRLMonotonic(t *testing.T) {
	f := newDualCAFixture(t)
	core, ref := f.client(t)
	order := f.ready(t, core)
	id := strings.TrimPrefix(order.Location, f.server.URL+"/acme/server/order/")
	csr := dualCSR(t)
	var wg sync.WaitGroup
	errorsCh := make(chan error, 8)
	for i := range 8 {
		wg.Go(func() { _, e := f.orders[i%2].Finalize(t.Context(), ref, id, csr); errorsCh <- e })
	}
	wg.Wait()
	close(errorsCh)
	for e := range errorsCh {
		if e != nil {
			t.Fatal(e)
		}
	}
	certificate, e := f.orders[1].Certificate(t.Context(), ref, id)
	if e != nil {
		t.Fatal(e)
	}
	revocation := domain.Revocation{Serial: certificate.Serial, Reason: 1, At: time.Now().UTC()}
	if e = postgres.NewRunner(f.pools[0]).Within(t.Context(), func(sc transaction.Scope) error { return repo.New().Revoke(sc, certificate.IssuerID, revocation) }); e != nil {
		t.Fatal(e)
	}
	numbers := make(chan int64, 8)
	failures := make(chan error, 8)
	for i := range 8 {
		wg.Go(func() {
			der, e := f.statuses[i%2].CRL(t.Context(), certificate.IssuerID)
			if e != nil {
				failures <- e
				return
			}
			crl, e := x509.ParseRevocationList(der)
			if e != nil {
				failures <- e
				return
			}
			if e = crl.CheckSignatureFrom(f.issuer.Certificate); e != nil {
				failures <- e
				return
			}
			if len(crl.RevokedCertificateEntries) != 1 {
				failures <- errors.New("revocation omitted from concurrent CRL")
				return
			}
			numbers <- crl.Number.Int64()
		})
	}
	wg.Wait()
	close(numbers)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	seen := map[int64]bool{}
	var max int64
	for n := range numbers {
		if n <= 0 || seen[n] {
			t.Fatal("duplicate/backward CRL number", n)
		}
		seen[n] = true
		if n > max {
			max = n
		}
	}
	if len(seen) != 8 {
		t.Fatal("concurrent CRLs incomplete")
	}
	restarted := statusapp.New(postgres.NewRunner(f.pools[1]), repo.New(), pkicrypto.NewStatusSigner(f.issuer), nil)
	der, e := restarted.CRL(t.Context(), certificate.IssuerID)
	if e != nil {
		t.Fatal(e)
	}
	crl, e := x509.ParseRevocationList(der)
	if e != nil || crl.Number.Int64() <= max {
		t.Fatal("CA restart regressed CRL number", e)
	}
	leaf, e := x509.ParseCertificate(certificate.DER)
	if e != nil {
		t.Fatal(e)
	}
	request, e := ocsp.CreateRequest(leaf, f.issuer.Certificate, nil)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := ocsp.ParseRequest(request)
	if e != nil {
		t.Fatal(e)
	}
	certID := statusapp.CertID{Hash: parsed.HashAlgorithm.String(), NameHash: parsed.IssuerNameHash, KeyHash: parsed.IssuerKeyHash, Serial: certificate.Serial}
	certID.Hash = "SHA-1"
	for _, instance := range f.statuses {
		response, e := instance.OCSP(t.Context(), certID)
		if e != nil {
			t.Fatal(e)
		}
		status, e := ocsp.ParseResponseForCert(response, leaf, f.issuer.Certificate)
		if e != nil || status.Status != ocsp.Revoked {
			t.Fatal("revoked leaf became good through peer", e)
		}
	}
}

// The test child exits after the real crypto signer returns and before the
// transaction can append a certificate. Its closed PG connection rolls back
// exactly as a lost CA process would; no simulated successful receipt is used.
type caCrashCommand struct {
	Database, Online, Identity, OrderID string
	Ref                                 app.AccountRef
	CSR                                 []byte
}
type exitingCASigner struct{ app.Signer }

func (s exitingCASigner) Sign(csr []byte, p domain.Policy, names []string, serial domain.Serial, now time.Time) (domain.IssuedCertificate, error) {
	certificate, e := s.Signer.Sign(csr, p, names, serial, now)
	if e != nil {
		return certificate, e
	}
	os.Exit(77)
	panic("unreachable")
}
func TestCAFinalizeCrashChild(t *testing.T) {
	path := os.Getenv("GATEBEAM_CA_CRASH_CHILD")
	if path == "" {
		t.Skip("owned subprocess helper")
	}
	body, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var command caCrashCommand
	if e = json.Unmarshal(body, &command); e != nil {
		t.Fatal(e)
	}
	pool, e := postgres.Open(t.Context(), bootstrap.Config{DatabaseFile: command.Database})
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(command.Online, "issuer.pem"), RootFile: filepath.Join(command.Online, "root.pem"), SignerFile: filepath.Join(command.Online, "issuer.age"), IdentityFile: command.Identity})
	if e != nil {
		t.Fatal(e)
	}
	service := app.NewOrders(postgres.NewRunner(pool), repo.New(), pkicrypto.Random{}, nil, exitingCASigner{pkicrypto.OrderSigner{Issuer: issuer}}, nil)
	if _, e = service.Finalize(t.Context(), command.Ref, command.OrderID, command.CSR); e != nil {
		t.Fatal(e)
	}
	t.Fatal("expected process loss did not occur")
}
