//go:build integration

package acme_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	management "gatebeam-ca/internal/modules/pki/application"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/domain"
	pkicrypto "gatebeam-ca/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam-ca/internal/modules/pki/infrastructure/jose"
	repo "gatebeam-ca/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam-ca/internal/modules/pki/transport/acme"
	"gatebeam-ca/internal/platform/audit"
	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/secrets"
	"gatebeam-ca/internal/platform/testkit"
	"gatebeam-ca/internal/platform/transaction"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type security struct{ tx transaction.Runner }

func (s security) Within(ctx context.Context, _ management.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}

type fixture struct {
	t       *testing.T
	db      *pgxpool.Pool
	server  *httptest.Server
	service *app.Service
	nonces  *app.Nonces
	grants  *management.GrantService
	now     time.Time
	ca      *secrets.Store
}

func newFixture(t *testing.T, listenAddress ...string) *fixture {
	t.Helper()
	f := &fixture{t: t, db: testkit.Postgres(t), now: time.Now().UTC()}
	identity := filepath.Join(t.TempDir(), "ca.key")
	if e := secrets.EnsureIdentity(identity); e != nil {
		t.Fatal(e)
	}
	ca, e := secrets.New(identity)
	if e != nil {
		t.Fatal(e)
	}
	f.ca = ca
	se, e := secrets.NewRecipient(ca.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	tx := postgres.NewRunner(f.db)
	store := repo.New()
	f.service = app.New(tx, store, pkicrypto.Random{}, ca, func() time.Time { return f.now })
	f.nonces = app.NewNonces(tx, store, pkicrypto.Random{}, func() time.Time { return f.now })
	ps, _ := domain.NewPolicy([]string{"host.example"}, domain.ServerAuth)
	pc, _ := domain.NewPolicy([]string{"client.example"}, domain.ClientAuth)
	f.grants = management.NewGrantService(security{tx}, store, se, pkicrypto.Random{}, audit.New(), map[string]domain.Policy{"server": ps, "client": pc}, func() time.Time { return f.now })
	f.server = httptest.NewUnstartedServer(nil)
	if len(listenAddress) > 0 {
		if e := f.server.Listener.Close(); e != nil {
			t.Fatal(e)
		}
		f.server.Listener, e = net.Listen("tcp", listenAddress[0])
		if e != nil {
			t.Fatal(e)
		}
	}
	f.server.StartTLS()
	f.server.Client().Timeout = 3 * time.Second
	t.Cleanup(f.server.Close)
	f.restart()
	return f
}
func (f *fixture) restart() {
	f.t.Helper()
	tx := postgres.NewRunner(f.db)
	f.service = app.New(tx, repo.New(), pkicrypto.Random{}, f.ca, func() time.Time { return f.now })
	s, e := transport.NewProtocol(f.server.URL, f.service, f.nonces, josecrypto.Crypto{}, app.NewOrders(tx, repo.New(), pkicrypto.Random{}, nil, nil, func() time.Time { return f.now }))
	if e != nil {
		f.t.Fatal(e)
	}
	f.server.Config.Handler = s
}
func (f *fixture) grant(directory string) (management.Grant, management.EABCredentials) {
	f.t.Helper()
	purpose := domain.ServerAuth
	name := "host.example"
	if directory == "client" {
		purpose = domain.ClientAuth
		name = "client.example"
	}
	g, e := f.grants.Authorize(context.Background(), management.ActorRef{UserID: "admin"}, management.GrantSpec{Names: []string{name}, Purpose: purpose, Directory: directory, Expires: f.now.Add(time.Hour)})
	if e != nil {
		f.t.Fatal(e)
	}
	b, e := f.grants.IssueEAB(context.Background(), management.ActorRef{UserID: "admin"}, g.ID)
	if e != nil {
		f.t.Fatal(e)
	}
	return g, b
}
func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func public(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, e := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func signed(t *testing.T, k any, algorithm jose.SignatureAlgorithm, url, nonce, kid string, payload []byte) []byte {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithHeader("url", url)
	if nonce != "" {
		opts.WithHeader("nonce", nonce)
	}
	if kid != "" {
		opts.WithHeader("kid", kid)
	} else {
		priv, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("key required")
		}
		opts.WithHeader("jwk", jose.JSONWebKey{Key: &priv.PublicKey})
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: k}, opts)
	if e != nil {
		t.Fatal(e)
	}
	if payload == nil {
		payload = []byte{}
	}
	message, e := signer.Sign(payload)
	if e != nil {
		t.Fatal(e)
	}
	return []byte(message.FullSerialize())
}
func (f *fixture) nonce() string {
	f.t.Helper()
	n, e := f.nonces.Issue(context.Background())
	if e != nil {
		f.t.Fatal(e)
	}
	return n
}
func (f *fixture) post(path string, raw []byte) (int, http.Header, []byte) {
	f.t.Helper()
	req, e := http.NewRequest("POST", f.server.URL+path, bytes.NewReader(raw))
	if e != nil {
		f.t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	response, e := f.server.Client().Do(req)
	if e != nil {
		f.t.Fatal(e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil {
		f.t.Fatal(e)
	}
	return response.StatusCode, response.Header, body
}
func (f *fixture) registration(k *ecdsa.PrivateKey, b management.EABCredentials, directory, nonce string) []byte {
	f.t.Helper()
	url := f.server.URL + "/acme/" + directory + "/new-account"
	secret, e := base64.RawURLEncoding.DecodeString(b.HMAC)
	if e != nil {
		f.t.Fatal(e)
	}
	proof := signed(f.t, secret, jose.HS256, url, "", b.KeyID, public(f.t, k))
	body, e := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": json.RawMessage(proof)})
	if e != nil {
		f.t.Fatal(e)
	}
	return signed(f.t, k, jose.ES256, url, nonce, "", body)
}
func (f *fixture) register(k *ecdsa.PrivateKey, b management.EABCredentials, d string) string {
	f.t.Helper()
	status, h, _ := f.post("/acme/"+d+"/new-account", f.registration(k, b, d, f.nonce()))
	if status != 201 {
		f.t.Fatalf("registration got %d", status)
	}
	return h.Get("Location")
}
func TestStandardDirectoryAndNonce(t *testing.T) {
	f := newFixture(t)
	for _, d := range []string{"server", "client"} {
		resp, e := f.server.Client().Get(f.server.URL + "/acme/" + d + "/directory")
		if e != nil {
			t.Fatal(e)
		}
		var value map[string]any
		e = json.NewDecoder(resp.Body).Decode(&value)
		resp.Body.Close()
		if e != nil || resp.StatusCode != 200 || value["newAccount"] != f.server.URL+"/acme/"+d+"/new-account" {
			t.Fatal("standard directory")
		}
	}
	for _, method := range []string{"HEAD", "GET"} {
		req, _ := http.NewRequest(method, f.server.URL+"/acme/server/new-nonce", nil)
		resp, e := f.server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := 204
		if method == "HEAD" {
			want = 200
		}
		if resp.StatusCode != want || len(b) != 0 || resp.Header.Get("Cache-Control") != "no-store" || len(resp.Header.Get("Replay-Nonce")) != 43 {
			t.Fatal("nonce HTTP semantics")
		}
	}
}
func TestEABIsBoundExpiringAndConsumedOnce(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	k := key(t)
	if status, _, _ := f.post("/acme/client/new-account", f.registration(k, b, "client", f.nonce())); status != 403 {
		t.Fatalf("wrong directory %d", status)
	}
	f.now = f.now.Add(16 * time.Minute)
	if status, _, _ := f.post("/acme/server/new-account", f.registration(k, b, "server", f.nonce())); status != 403 {
		t.Fatalf("expired EAB %d", status)
	}
	_, fresh := f.grant("server")
	keys := []*ecdsa.PrivateKey{key(t), key(t)}
	raw := [][]byte{f.registration(keys[0], fresh, "server", f.nonce()), f.registration(keys[1], fresh, "server", f.nonce())}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for _, body := range raw {
		wg.Go(func() { status, _, _ := f.post("/acme/server/new-account", body); results <- status })
	}
	wg.Wait()
	close(results)
	success, denied := 0, 0
	for v := range results {
		if v == 201 {
			success++
		}
		if v == 403 {
			denied++
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("concurrent bindings success=%d denied=%d", success, denied)
	}
	var count int
	if e := f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_accounts").Scan(&count); e != nil || count != 1 {
		t.Fatal("atomic binding", e, count)
	}
}
func TestReplayAndKeyChange(t *testing.T) {
	f := newFixture(t)
	g, b := f.grant("server")
	old := key(t)
	raw := f.registration(old, b, "server", f.nonce())
	status, h, _ := f.post("/acme/server/new-account", raw)
	if status != 201 {
		t.Fatal(status)
	}
	kid := h.Get("Location")
	if status, h, body := f.post("/acme/server/new-account", raw); status != 400 || h.Get("Replay-Nonce") == "" || !bytes.Contains(body, []byte("badNonce")) {
		t.Fatal("replay accepted")
	}
	f.now = f.now.Add(16 * time.Minute)
	f.restart()
	url := f.server.URL + "/acme/server/new-account"
	request := signed(t, old, jose.ES256, url, f.nonce(), "", []byte(`{"onlyReturnExisting":true}`))
	if status, h, _ := f.post("/acme/server/new-account", request); status != 200 || h.Get("Location") != kid {
		t.Fatal("restart required EAB", status)
	}
	next := key(t)
	changeURL := f.server.URL + "/acme/server/key-change"
	body, _ := json.Marshal(map[string]any{"account": kid, "oldKey": json.RawMessage(public(t, old))})
	inner := signed(t, next, jose.ES256, changeURL, "", "", body)
	outer := signed(t, old, jose.ES256, changeURL, f.nonce(), kid, inner)
	if status, _, _ := f.post("/acme/server/key-change", outer); status != 200 {
		t.Fatal("key rollover", status)
	}
	path := strings.TrimPrefix(kid, f.server.URL)
	if status, _, _ := f.post(path, signed(t, old, jose.ES256, kid, f.nonce(), kid, nil)); status == 200 {
		t.Fatal("old key survived rollover")
	}
	if status, _, _ := f.post(path, signed(t, next, jose.ES256, kid, f.nonce(), kid, nil)); status != 200 {
		t.Fatal("POST-as-GET failed", status)
	}
	if e := f.grants.DisablePrincipal(context.Background(), management.ActorRef{UserID: "admin"}, g.Principal.ID); e != nil {
		t.Fatal(e)
	}
	if status, _, _ := f.post(path, signed(t, next, jose.ES256, kid, f.nonce(), kid, nil)); status != 403 {
		t.Fatal("disabled principal permitted", status)
	}
}
func TestFailedBusinessRequestStillConsumesNonce(t *testing.T) {
	f := newFixture(t)
	k := key(t)
	_, b := f.grant("client")
	raw := f.registration(k, b, "server", f.nonce())
	if status, _, _ := f.post("/acme/server/new-account", raw); status != 403 {
		t.Fatal(status)
	}
	if status, _, body := f.post("/acme/server/new-account", raw); status != 400 || !bytes.Contains(body, []byte("badNonce")) {
		t.Fatal("failed business revived nonce")
	}
	raw = signed(t, k, jose.ES256, f.server.URL+"/wrong-url", f.nonce(), "", []byte(`{}`))
	if status, _, _ := f.post("/acme/server/new-account", raw); status != 403 {
		t.Fatal("URL accepted")
	}
	if _, _, body := f.post("/acme/server/new-account", raw); !bytes.Contains(body, []byte("badNonce")) {
		t.Fatal("invalid URL revived valid signature nonce")
	}
}

type failAudit struct{}

func (failAudit) Append(transaction.Scope, audit.Event) error {
	return errors.New("owned audit failure")
}
func TestManagementFailureRollsBackAndNeverReturnsHMAC(t *testing.T) {
	f := newFixture(t)
	g, _ := f.grant("server")
	se, _ := secrets.NewRecipient(f.ca.Recipient())
	service := management.NewGrantService(security{postgres.NewRunner(f.db)}, repo.New(), se, pkicrypto.Random{}, failAudit{}, nil, func() time.Time { return f.now })
	got, e := service.IssueEAB(context.Background(), management.ActorRef{UserID: "admin"}, g.ID)
	if e == nil || got.HMAC != "" || got.KeyID != "" {
		t.Fatal("secret escaped failed audit")
	}
	var count int
	if e = f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_eab WHERE NOT consumed").Scan(&count); e != nil || count != 1 {
		t.Fatal("failed replacement revoked original", e)
	}
}

func TestInvalidEABDoesNotConsumeBindingAndAccountFailureDoesNotReviveNonce(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	k := key(t)
	other := key(t)
	url := f.server.URL + "/acme/server/new-account"
	secret, _ := base64.RawURLEncoding.DecodeString(b.HMAC)
	proof := signed(t, secret, jose.HS256, url, "", b.KeyID, public(t, other))
	body, _ := json.Marshal(map[string]any{"externalAccountBinding": json.RawMessage(proof)})
	raw := signed(t, k, jose.ES256, url, f.nonce(), "", body)
	if status, _, _ := f.post("/acme/server/new-account", raw); status != 403 {
		t.Fatal("wrong EAB public key accepted", status)
	}
	var used bool
	if e := f.db.QueryRow(context.Background(), "SELECT consumed FROM pki_eab WHERE id=$1", b.KeyID).Scan(&used); e != nil || used {
		t.Fatal("invalid EAB consumed", e)
	}
	f.register(k, b, "server")
}
func TestNestedRolloverRejectsWrongAccountOldKeyURLAndNonce(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	old := key(t)
	kid := f.register(old, b, "server")
	next := key(t)
	url := f.server.URL + "/acme/server/key-change"
	cases := []struct {
		name, account, url, nonce string
		old                       *ecdsa.PrivateKey
	}{
		{"account", kid + "x", url, "", old}, {"url", kid, url + "x", "", old}, {"nonce", kid, url, "unexpected", old}, {"oldKey", kid, url, "", key(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"account": tc.account, "oldKey": json.RawMessage(public(t, tc.old))})
			inner := signed(t, next, jose.ES256, tc.url, tc.nonce, "", body)
			outer := signed(t, old, jose.ES256, url, f.nonce(), kid, inner)
			if status, _, _ := f.post("/acme/server/key-change", outer); status != 400 {
				t.Fatal("invalid rollover accepted", status)
			}
		})
	}
	path := strings.TrimPrefix(kid, f.server.URL)
	if status, _, _ := f.post(path, signed(t, old, jose.ES256, kid, f.nonce(), kid, []byte{})); status != 200 {
		t.Fatal("invalid rollover modified current key", status)
	}
}
func TestNonceExpiryAndBoundedCleanup(t *testing.T) {
	f := newFixture(t)
	nonce := f.nonce()
	f.now = f.now.Add(11 * time.Minute)
	if e := f.nonces.Consume(context.Background(), nonce); !errors.Is(e, app.ErrBadNonce) {
		t.Fatal("expired nonce accepted", e)
	}
	if _, e := f.db.Exec(context.Background(), "INSERT INTO pki_nonces(digest,expires) SELECT 'owned-'||n,now()-interval '1 hour' FROM generate_series(1,300) n"); e != nil {
		t.Fatal(e)
	}
	_ = f.nonce()
	var left int
	if e := f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_nonces WHERE digest LIKE 'owned-%'").Scan(&left); e != nil || left != 172 {
		t.Fatal("unbounded cleanup", e, left)
	}
}
func TestReplacementEABInvalidatesLostCredential(t *testing.T) {
	f := newFixture(t)
	g, old := f.grant("server")
	fresh, e := f.grants.IssueEAB(context.Background(), management.ActorRef{UserID: "admin"}, g.ID)
	if e != nil {
		t.Fatal(e)
	}
	k := key(t)
	if status, _, _ := f.post("/acme/server/new-account", f.registration(k, old, "server", f.nonce())); status != 403 {
		t.Fatal("replaced EAB accepted", status)
	}
	f.register(k, fresh, "server")
}

func TestAccountTransactionRollbackNeverRevivesNonce(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	ctx := context.Background()
	k := key(t)
	if _, e := f.db.Exec(ctx, `CREATE FUNCTION reject_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned binding failure'; END $$; CREATE TRIGGER owned_failure BEFORE UPDATE ON pki_eab FOR EACH ROW EXECUTE FUNCTION reject_binding()`); e != nil {
		t.Fatal(e)
	}
	raw := f.registration(k, b, "server", f.nonce())
	if status, _, _ := f.post("/acme/server/new-account", raw); status != 503 {
		t.Fatal("injected write failure not propagated", status)
	}
	var accounts int
	if e := f.db.QueryRow(ctx, "SELECT count(*) FROM pki_accounts").Scan(&accounts); e != nil || accounts != 0 {
		t.Fatal("account survived binding rollback", e)
	}
	if _, e := f.db.Exec(ctx, "DROP TRIGGER owned_failure ON pki_eab; DROP FUNCTION reject_binding()"); e != nil {
		t.Fatal(e)
	}
	if status, _, body := f.post("/acme/server/new-account", raw); status != 400 || !bytes.Contains(body, []byte("badNonce")) {
		t.Fatal("transaction rollback revived nonce")
	}
	f.register(k, b, "server")
}
func TestCommitFailureDoesNotReturnEABOrReplaceCredential(t *testing.T) {
	f := newFixture(t)
	g, b := f.grant("server")
	ctx := context.Background()
	if _, e := f.db.Exec(ctx, `CREATE FUNCTION reject_audit_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned commit failure'; END $$; CREATE CONSTRAINT TRIGGER owned_commit_failure AFTER INSERT ON audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_audit_commit()`); e != nil {
		t.Fatal(e)
	}
	out, e := f.grants.IssueEAB(ctx, management.ActorRef{UserID: "admin"}, g.ID)
	if e == nil || out.HMAC != "" || out.KeyID != "" {
		t.Fatal("secret returned before failed commit")
	}
	var used bool
	if e = f.db.QueryRow(ctx, "SELECT consumed FROM pki_eab WHERE id=$1", b.KeyID).Scan(&used); e != nil || used {
		t.Fatal("failed commit replaced credential", e)
	}
}

func TestConsumedBindingCannotBeRevivedByDatabaseWriter(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	f.register(key(t), b, "server")
	if _, e := f.db.Exec(context.Background(), "UPDATE pki_eab SET consumed=false WHERE id=$1", b.KeyID); e == nil {
		t.Fatal("consumed EAB revived")
	}
}

func TestRFC8555BootstrapPostAsGetAndErrorFields(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	k := key(t)
	kid := f.register(k, b, "server")
	for _, resource := range []string{"directory", "new-nonce"} {
		t.Run(resource, func(t *testing.T) {
			path := "/acme/server/" + resource
			raw := signed(t, k, jose.ES256, f.server.URL+path, f.nonce(), kid, []byte{})
			status, h, body := f.post(path, raw)
			want := 200
			if resource == "new-nonce" {
				want = 204
			}
			if status != want || h.Get("Replay-Nonce") == "" {
				t.Fatalf("POST-as-GET bootstrap status=%d want=%d", status, want)
			}
			if resource == "new-nonce" && len(body) != 0 {
				t.Fatal("newNonce body not empty")
			}
		})
	}
	path := "/acme/server/new-account"
	url := f.server.URL + path
	if status, h, body := f.post(path, signed(t, k, jose.ES256, url, "", "", []byte(`{}`))); status != 400 || h.Get("Replay-Nonce") == "" || !bytes.Contains(body, []byte("badNonce")) {
		t.Fatal("missing nonce must be badNonce")
	}
	raw := signed(t, make([]byte, 32), jose.HS256, url, f.nonce(), "not-an-account", []byte(`{}`))
	status, _, body := f.post(path, raw)
	var problem struct{ Algorithms []string }
	_ = json.Unmarshal(body, &problem)
	if status != 400 || len(problem.Algorithms) != 3 || !bytes.Contains(body, []byte("badSignatureAlgorithm")) {
		t.Fatal("unsupported algorithm problem lacks supported algorithms")
	}
	raw = signed(t, k, jose.ES256, url+"-wrong", f.nonce(), "", []byte(`{}`))
	status, _, body = f.post(path, raw)
	if status != 403 || !bytes.Contains(body, []byte("unauthorized")) {
		t.Fatal("URL mismatch must be unauthorized")
	}
}

func TestNewAccountEchoesExactlyVerifiedBindingAfterCommit(t *testing.T) {
	f := newFixture(t)
	_, binding := f.grant("server")
	k := key(t)
	path := "/acme/server/new-account"
	url := f.server.URL + path
	secret, e := base64.RawURLEncoding.DecodeString(binding.HMAC)
	if e != nil {
		t.Fatal(e)
	}
	proof := signed(t, secret, jose.HS256, url, "", binding.KeyID, public(t, k))
	payload, e := json.Marshal(map[string]any{"externalAccountBinding": json.RawMessage(proof)})
	if e != nil {
		t.Fatal(e)
	}
	status, header, body := f.post(path, signed(t, k, jose.ES256, url, f.nonce(), "", payload))
	if status != 201 {
		t.Fatal("new account rejected", status)
	}
	var response struct {
		Binding json.RawMessage `json:"externalAccountBinding"`
	}
	if json.Unmarshal(body, &response) != nil || !bytes.Equal(response.Binding, proof) {
		t.Fatal("successful registration did not echo identical verified binding JWS")
	}
	var consumed bool
	if e = f.db.QueryRow(context.Background(), "SELECT consumed FROM pki_eab WHERE id=$1", binding.KeyID).Scan(&consumed); e != nil || !consumed {
		t.Fatal("binding response preceded committed consumption", e)
	}
	var accounts int
	if e = f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_accounts WHERE id=$1", strings.TrimPrefix(header.Get("Location"), f.server.URL+"/acme/server/account/")).Scan(&accounts); e != nil || accounts != 1 {
		t.Fatal("binding response preceded committed account", e)
	}
	// Existing-key lookup ignores registration fields and must not reflect an
	// unverified supplied proof, even when that public JWS was once valid.
	status, _, body = f.post(path, signed(t, k, jose.ES256, url, f.nonce(), "", payload))
	response.Binding = nil
	if status != 200 || json.Unmarshal(body, &response) != nil || len(response.Binding) != 0 {
		t.Fatal("existing account reflected unverified binding")
	}
}

func TestAccountContactUpdateIgnoresStatusExceptDeactivation(t *testing.T) {
	f := newFixture(t)
	_, binding := f.grant("server")
	k := key(t)
	kid := f.register(k, binding, "server")
	path := strings.TrimPrefix(kid, f.server.URL)
	read := func(payload []byte) (int, string, []string) {
		t.Helper()
		status, _, body := f.post(path, signed(t, k, jose.ES256, kid, f.nonce(), kid, payload))
		if status != 200 {
			return status, "", nil
		}
		var account struct {
			Status   string   `json:"status"`
			Contacts []string `json:"contact"`
		}
		if json.Unmarshal(body, &account) != nil {
			t.Fatal("invalid account response")
		}
		return status, account.Status, account.Contacts
	}
	status, state, contacts := read([]byte(`{"status":"valid","contact":["mailto:ops@example.org"]}`))
	if status != 200 || state != "valid" || len(contacts) != 1 || contacts[0] != "mailto:ops@example.org" {
		t.Fatal("valid status blocked contact update", status)
	}
	var stored []string
	if e := f.db.QueryRow(context.Background(), "SELECT contacts FROM pki_accounts WHERE id=$1", strings.TrimPrefix(kid, f.server.URL+"/acme/server/account/")).Scan(&stored); e != nil || len(stored) != 1 || stored[0] != "mailto:ops@example.org" {
		t.Fatal("contact update not committed", e)
	}
	for _, ignored := range []string{`"valid"`, `"revoked"`, `"pending"`, `{"unknown":true}`} {
		status, state, contacts = read([]byte(`{"status":` + ignored + `}`))
		if status != 200 || state != "valid" || len(contacts) != 1 || contacts[0] != "mailto:ops@example.org" {
			t.Fatal("ignored status changed account or contacts", status)
		}
	}
	status, state, contacts = read([]byte{})
	if status != 200 || state != "valid" || len(contacts) != 1 || contacts[0] != "mailto:ops@example.org" {
		t.Fatal("ignored update persisted side effects", status)
	}
	status, state, _ = read([]byte(`{"status":"deactivated"}`))
	if status != 200 || state != "deactivated" {
		t.Fatal("explicit deactivation no longer works", status)
	}
	status, _, _ = read([]byte{})
	if status != 401 {
		t.Fatal("deactivated account must be unauthorized401", status)
	}
}

func TestAccountContactWireErrors(t *testing.T) {
	f := newFixture(t)
	_, binding := f.grant("server")
	k := key(t)
	kid := f.register(k, binding, "server")
	for _, tc := range []struct{ contact, kind string }{{"tel:+1234", "unsupportedContact"}, {"mailto:invalid", "invalidContact"}, {"mailto:Display <a@example.org>", "invalidContact"}, {"mailto:a@example.org?subject=test", "invalidContact"}, {"mailto:a@example.org,b@example.org", "invalidContact"}} {
		for _, existing := range []bool{false, true} {
			path := "/acme/server/new-account"
			accountKey := key(t)
			accountID := ""
			if existing {
				path = strings.TrimPrefix(kid, f.server.URL)
				accountKey = k
				accountID = kid
			}
			payload, _ := json.Marshal(map[string]any{"contact": []string{tc.contact}})
			code, _, body := f.post(path, signed(t, accountKey, jose.ES256, f.server.URL+path, f.nonce(), accountID, payload))
			var problem struct {
				Type, Detail string
				Status       int
			}
			json.Unmarshal(body, &problem)
			if code != 400 || problem.Status != 400 || problem.Type != "urn:ietf:params:acme:error:"+tc.kind {
				t.Errorf("existing=%v contact=%q got%d %s", existing, tc.contact, code, body)
			}
			if tc.kind == "unsupportedContact" && !strings.Contains(problem.Detail, "mailto") {
				t.Error("supported contact scheme absent")
			}
		}
	}
}
func TestDeactivatedAccountWireRejectsEveryAccountOperation(t *testing.T) {
	f := newFixture(t)
	_, binding := f.grant("server")
	k := key(t)
	kid := f.register(k, binding, "server")
	path := strings.TrimPrefix(kid, f.server.URL)
	code, _, _ := f.post(path, signed(t, k, jose.ES256, kid, f.nonce(), kid, []byte(`{"status":"deactivated"}`)))
	if code != 200 {
		t.Fatal(code)
	}
	for _, suffix := range []string{"directory", "new-nonce", "account/" + strings.TrimPrefix(kid, f.server.URL+"/acme/server/account/"), "new-order", "key-change", "revoke-cert", "account/" + strings.TrimPrefix(kid, f.server.URL+"/acme/server/account/") + "/orders"} {
		path := "/acme/server/" + suffix
		code, _, body := f.post(path, signed(t, k, jose.ES256, f.server.URL+path, f.nonce(), kid, []byte{}))
		var problem struct {
			Type   string
			Status int
		}
		json.Unmarshal(body, &problem)
		if code != 401 || problem.Status != 401 || problem.Type != "urn:ietf:params:acme:error:unauthorized" {
			t.Errorf("%s got%d %s", suffix, code, body)
		}
	}
}
