//go:build integration

package acme_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	management "gatebeam-ca/internal/modules/pki/application"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/domain"
	pkicrypto "gatebeam-ca/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam-ca/internal/modules/pki/infrastructure/jose"
	repo "gatebeam-ca/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam-ca/internal/modules/pki/transport/acme"
	"gatebeam-ca/internal/platform/postgres"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOrderNamesAndCSRMustMatchGrant(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	k := key(t)
	kid := f.register(k, b, "server")
	path := "/acme/server/new-order"
	for _, tc := range []struct {
		name string
		want int
	}{{"host.example", 201}, {"other.example", 403}, {"*.host.example", 403}} {
		payload, _ := json.Marshal(map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": tc.name}}})
		status, _, body := f.post(path, signed(t, k, "ES256", f.server.URL+path, f.nonce(), kid, payload))
		if status != tc.want {
			t.Fatalf("order %s status %d want %d: %s", tc.name, status, tc.want, body)
		}
	}
}

// These tests exercise the application against PostgreSQL and the P1 issuer.
// Only the slow external HTTP hop is replaced, to synchronize revocation races.
type validationFunc func(context.Context, string, string, string) error

func (v validationFunc) Validate(c context.Context, n, t, k string) error { return v(c, n, t, k) }
func issuerForOrders(t *testing.T) pkicrypto.Issuer {
	t.Helper()
	dir := t.TempDir()
	cmd := management.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: filepath.Join(dir, "online"), RootName: "test root", IntermediateName: "test issuer"}
	if e := (pkicrypto.Bootstrapper{}).Generate(context.Background(), cmd); e != nil {
		t.Fatal(e)
	}
	i, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(cmd.OnlineDirectory, "issuer.pem"), RootFile: filepath.Join(cmd.OnlineDirectory, "root.pem"), SignerFile: filepath.Join(cmd.OnlineDirectory, "issuer.age"), IdentityFile: filepath.Join(cmd.OnlineDirectory, "identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	return i
}
func ordersFor(t *testing.T, f *fixture, v app.HTTP01) *app.OrderService {
	t.Helper()
	i := issuerForOrders(t)
	f.now = time.Now().UTC()
	tx := postgres.NewRunner(f.db)
	store := repo.New()
	if e := management.NewRegistry(tx, store).Register(context.Background(), i.Metadata(), i.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	return app.NewOrders(tx, store, pkicrypto.Random{}, v, pkicrypto.OrderSigner{Issuer: i}, func() time.Time { return f.now })
}
func orderRef(t *testing.T, f *fixture) (management.Grant, app.AccountRef) {
	t.Helper()
	g, b := f.grant("server")
	k := key(t)
	kid := f.register(k, b, "server")
	pub, e := (josecrypto.Crypto{}).PublicKey(public(t, k))
	if e != nil {
		t.Fatal(e)
	}
	return g, app.AccountRef{Directory: "server", ID: strings.TrimPrefix(kid, f.server.URL+"/acme/server/account/"), Thumbprint: pub.Thumbprint}
}
func csrFor(t *testing.T, names ...string) []byte {
	t.Helper()
	k := key(t)
	b, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, k)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func readyOrder(t *testing.T, s *app.OrderService, ref app.AccountRef) domain.Order {
	t.Helper()
	o, e := s.NewOrder(context.Background(), ref, []string{"host.example"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Finalize(context.Background(), ref, o.ID, csrFor(t, "host.example")); !errors.Is(e, app.ErrOrderNotReady) {
		t.Fatal("unproved finalize", e)
	}
	o, e = s.Challenge(context.Background(), ref, o.ID, o.Challenges[0].ID)
	if e != nil || o.Status != "ready" {
		t.Fatal("proof not ready", e)
	}
	return o
}
func TestFinalizeIsDurableAndIdempotent(t *testing.T) {
	f := newFixture(t)
	_, ref := orderRef(t, f)
	s := ordersFor(t, f, validationFunc(func(context.Context, string, string, string) error { return nil }))
	o := readyOrder(t, s, ref)
	if _, e := s.Finalize(context.Background(), ref, o.ID, csrFor(t, "host.example", "other.example")); !errors.Is(e, app.ErrBadCSR) {
		t.Fatal("added CSR SAN accepted", e)
	}
	csr := csrFor(t, "host.example")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, e := s.Finalize(context.Background(), ref, o.ID, csr); errs <- e })
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	c, e := s.Certificate(context.Background(), ref, o.ID)
	if e != nil {
		t.Fatal(e)
	}
	var count, serials int
	if e = f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_certificates").Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate certificate", count, e)
	}
	if e = f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_serial_reservations").Scan(&serials); e != nil || serials != 1 {
		t.Fatal("failed CSR reserved serial or duplicate issuance", serials, e)
	}
	restarted := app.NewOrders(postgres.NewRunner(f.db), repo.New(), pkicrypto.Random{}, nil, nil, func() time.Time { return f.now })
	if _, e = restarted.Finalize(context.Background(), ref, o.ID, []byte("retry")); e != nil {
		t.Fatal("retry demanded signer", e)
	}
	again, e := restarted.Certificate(context.Background(), ref, o.ID)
	if e != nil || !bytes.Equal(again.DER, c.DER) {
		t.Fatal("restart lost stored certificate", e)
	}
	_, other := orderRef(t, f)
	if _, e = restarted.Order(context.Background(), other, o.ID); !errors.Is(e, app.ErrOrderNotFound) {
		t.Fatal("cross-account access", e)
	}
	if _, e = restarted.Certificate(context.Background(), other, o.ID); !errors.Is(e, app.ErrOrderNotFound) {
		t.Fatal("cross-account certificate", e)
	}
}
func TestFinalizeCommitFailureDoesNotExposeCertificate(t *testing.T) {
	f := newFixture(t)
	_, ref := orderRef(t, f)
	s := ordersFor(t, f, validationFunc(func(context.Context, string, string, string) error { return nil }))
	o := readyOrder(t, s, ref)
	_, e := f.db.Exec(context.Background(), `CREATE FUNCTION fail_certificate_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned commit failure'; END $$; CREATE CONSTRAINT TRIGGER owned_commit_failure AFTER INSERT ON pki_certificates DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_certificate_commit()`)
	if e != nil {
		t.Fatal(e)
	}
	result, e := s.Finalize(context.Background(), ref, o.ID, csrFor(t, "host.example"))
	if e == nil || result.ID != "" {
		t.Fatal("failed commit returned success")
	}
	c, e := s.Certificate(context.Background(), ref, o.ID)
	if e == nil || len(c.DER) > 0 {
		t.Fatal("failed commit exposed bytes")
	}
	var count int
	if e = f.db.QueryRow(context.Background(), "SELECT count(*) FROM pki_serial_reservations").Scan(&count); e != nil || count != 0 {
		t.Fatal("rollback leaked serial", e, count)
	}
}
func TestChallengeRechecksDisableAndAccountRevisionOutsideDatabaseLocks(t *testing.T) {
	for _, change := range []string{"disable", "rollover", "rollover-back", "deactivate"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			g, ref := orderRef(t, f)
			entered, release := make(chan struct{}), make(chan struct{})
			s := ordersFor(t, f, validationFunc(func(context.Context, string, string, string) error { close(entered); <-release; return nil }))
			o, e := s.NewOrder(context.Background(), ref, []string{"host.example"})
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { _, e := s.Challenge(context.Background(), ref, o.ID, o.Challenges[0].ID); done <- e }()
			<-entered
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch change {
			case "disable":
				e = f.grants.DisablePrincipal(ctx, management.ActorRef{UserID: "admin"}, g.Principal.ID)
			case "deactivate":
				_, e = f.service.Current(ctx, ref.Directory, ref.ID, ref.Thumbprint, nil, true)
			default:
				current, e2 := f.service.Lookup(ctx, ref.Directory, ref.ID, "")
				if e2 != nil {
					t.Fatal(e2)
				}
				next, e2 := (josecrypto.Crypto{}).PublicKey(public(t, key(t)))
				if e2 != nil {
					t.Fatal(e2)
				}
				_, e = f.service.ChangeKey(ctx, ref.Directory, ref.ID, ref.Thumbprint, next)
				if e == nil && change == "rollover-back" {
					_, e = f.service.ChangeKey(ctx, ref.Directory, ref.ID, next.Thumbprint, app.PublicKey{Encoded: current.Key, Thumbprint: ref.Thumbprint})
				}
			}
			close(release)
			if e != nil {
				t.Fatal("network validator held database lock", e)
			}
			if e = <-done; !errors.Is(e, app.ErrDenied) {
				t.Fatal("stale proof completed", e)
			}
			var state string
			if e = f.db.QueryRow(context.Background(), "SELECT status FROM pki_orders WHERE id=$1", o.ID).Scan(&state); e != nil || state != "pending" {
				t.Fatal("stale proof persisted", e, state)
			}
		})
	}
}
func TestCompletedOrderStillChecksCurrentAuthority(t *testing.T) {
	f := newFixture(t)
	g, ref := orderRef(t, f)
	s := ordersFor(t, f, validationFunc(func(context.Context, string, string, string) error { return nil }))
	o := readyOrder(t, s, ref)
	if _, e := s.Finalize(context.Background(), ref, o.ID, csrFor(t, "host.example")); e != nil {
		t.Fatal(e)
	}
	if e := f.grants.DisablePrincipal(context.Background(), management.ActorRef{UserID: "admin"}, g.Principal.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Finalize(context.Background(), ref, o.ID, csrFor(t, "host.example")); !errors.Is(e, app.ErrDenied) {
		t.Fatal("completed retry bypassed disable", e)
	}
	if _, e := s.Certificate(context.Background(), ref, o.ID); !errors.Is(e, app.ErrDenied) {
		t.Fatal("certificate bypassed disable", e)
	}
}
func TestIndependentConcurrentChallengesDoNotInvalidateEachOther(t *testing.T) {
	f := newFixture(t)
	g, ref := orderRef(t, f)
	if _, e := f.db.Exec(context.Background(), "UPDATE pki_principals SET names=ARRAY['host.example','second.example'] WHERE id=$1", g.Principal.ID); e != nil {
		t.Fatal(e)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	s := ordersFor(t, f, validationFunc(func(context.Context, string, string, string) error { entered <- struct{}{}; <-release; return nil }))
	o, e := s.NewOrder(context.Background(), ref, []string{"host.example", "second.example"})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 2)
	for _, c := range o.Challenges {
		go func() { _, e := s.Challenge(context.Background(), ref, o.ID, c.ID); done <- e }()
	}
	<-entered
	<-entered
	close(release)
	for range 2 {
		if e = <-done; e != nil {
			t.Fatal("independent proof lost", e)
		}
	}
	o, e = s.Order(context.Background(), ref, o.ID)
	if e != nil || o.Status != "ready" {
		t.Fatal("independent challenges not ready", e)
	}
}
func TestStandardOrderRetrievalAndAccountOrders(t *testing.T) {
	f := newFixture(t)
	_, b := f.grant("server")
	k := key(t)
	kid := f.register(k, b, "server")
	path := "/acme/server/new-order"
	status, h, _ := f.post(path, signed(t, k, "ES256", f.server.URL+path, f.nonce(), kid, []byte(`{"identifiers":[{"type":"dns","value":"host.example"}]}`)))
	if status != 201 {
		t.Fatal(status)
	}
	orderURL := h.Get("Location")
	get := func(url string, payload []byte) (int, []byte) {
		s, _, b := f.post(strings.TrimPrefix(url, f.server.URL), signed(t, k, "ES256", url, f.nonce(), kid, payload))
		return s, b
	}
	status, body := get(kid+"/orders", nil)
	var list struct{ Orders []string }
	if json.Unmarshal(body, &list) != nil || status != 200 || len(list.Orders) != 1 || list.Orders[0] != orderURL {
		t.Fatal("account order retrieval", status, string(body))
	}
	status, body = get(orderURL, nil)
	var o struct {
		Status         string
		Authorizations []string
	}
	if json.Unmarshal(body, &o) != nil || status != 200 || o.Status != "pending" || len(o.Authorizations) != 1 {
		t.Fatal("order POST-as-GET")
	}
	if status, _ = get(o.Authorizations[0], nil); status != 200 {
		t.Fatal("authorization POST-as-GET", status)
	}
	if status, _ = get(orderURL, []byte(`{}`)); status != 400 {
		t.Fatal("order accepted nonempty payload", status)
	}
}
func TestFinalizationRejectsDangerousCSRAndCurrentGrantShrink(t *testing.T) {
	f := newFixture(t)
	g, ref := orderRef(t, f)
	s := ordersFor(t, f, validationFunc(func(context.Context, string, string, string) error { return nil }))
	o := readyOrder(t, s, ref)
	k := key(t)
	dangerous, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"host.example"}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}}}}, k)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Finalize(context.Background(), ref, o.ID, dangerous); !errors.Is(e, app.ErrBadCSR) {
		t.Fatal("CA extension accepted", e)
	}
	forged := csrFor(t, "host.example")
	forged[len(forged)-1] ^= 1
	if _, e = s.Finalize(context.Background(), ref, o.ID, forged); !errors.Is(e, app.ErrBadCSR) {
		t.Fatal("invalid CSR proof accepted", e)
	}
	if _, e = f.db.Exec(context.Background(), "UPDATE pki_principals SET names=ARRAY['other.example'] WHERE id=$1", g.Principal.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Finalize(context.Background(), ref, o.ID, csrFor(t, "host.example")); !errors.Is(e, app.ErrDenied) {
		t.Fatal("changed grant not rechecked", e)
	}
}

// A harmless account read during the outside-transaction network proof must not
// invalidate that proof or write the account row. Real key/status changes still
// invalidate it, covered by TestChallengeRechecksDisableAndAccountRevisionOutsideDatabaseLocks.
func TestReadOnlyAccountRequestsDoNotInvalidateHTTP01Proof(t *testing.T) {
	for _, kind := range []string{"post-as-get", "only-return-existing"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			_, binding := f.grant("server")
			k := key(t)
			kid := f.register(k, binding, "server")
			pub, e := (josecrypto.Crypto{}).PublicKey(public(t, k))
			if e != nil {
				t.Fatal(e)
			}
			ref := app.AccountRef{Directory: "server", ID: strings.TrimPrefix(kid, f.server.URL+"/acme/server/account/"), Thumbprint: pub.Thumbprint}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			orders := ordersFor(t, f, validationFunc(func(ctx context.Context, name, token, authorization string) error {
				if name != "host.example" || authorization != token+"."+pub.Thumbprint {
					return errors.New("incorrect validation input")
				}
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}))
			protocol, e := transport.NewProtocol(f.server.URL, f.service, f.nonces, josecrypto.Crypto{}, orders)
			if e != nil {
				t.Fatal(e)
			}
			f.server.Config.Handler = protocol
			order, e := orders.NewOrder(context.Background(), ref, []string{"host.example"})
			if e != nil {
				t.Fatal(e)
			}
			challengePath := "/acme/server/challenge/" + order.ID + "/" + order.Challenges[0].ID
			raw := signed(t, k, "ES256", f.server.URL+challengePath, f.nonce(), kid, []byte(`{}`))
			done := make(chan int, 1)
			go func() { status, _, _ := f.post(challengePath, raw); done <- status }()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("validation did not start")
			}
			var beforeRevision int64
			var beforeRow, beforeXmin string
			if e = f.db.QueryRow(context.Background(), "SELECT revision,to_jsonb(a)::text,xmin::text FROM pki_accounts a WHERE id=$1", ref.ID).Scan(&beforeRevision, &beforeRow, &beforeXmin); e != nil {
				t.Fatal(e)
			}
			path := strings.TrimPrefix(kid, f.server.URL)
			readKeyID := kid
			var payload []byte
			if kind == "only-return-existing" {
				path = "/acme/server/new-account"
				readKeyID = ""
				payload = []byte(`{"onlyReturnExisting":true}`)
			}
			status, _, body := f.post(path, signed(t, k, "ES256", f.server.URL+path, f.nonce(), readKeyID, payload))
			if status != 200 {
				t.Fatalf("read-only request status %d: %s", status, body)
			}
			var afterRevision int64
			var afterRow, afterXmin string
			if e = f.db.QueryRow(context.Background(), "SELECT revision,to_jsonb(a)::text,xmin::text FROM pki_accounts a WHERE id=$1", ref.ID).Scan(&afterRevision, &afterRow, &afterXmin); e != nil {
				t.Fatal(e)
			}
			if afterRevision != beforeRevision || afterRow != beforeRow || afterXmin != beforeXmin {
				t.Errorf("read-only account request wrote account row: revision %d -> %d, xmin %s -> %s", beforeRevision, afterRevision, beforeXmin, afterXmin)
			}
			unblock()
			select {
			case status = <-done:
				if status != 200 {
					t.Errorf("successful HTTP-01 proof rejected after read-only account request: %d", status)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("challenge did not complete")
			}
			current, e := orders.Order(context.Background(), ref, order.ID)
			if e != nil || current.Status != "ready" {
				t.Fatalf("proof did not produce ready order: status=%s err=%v", current.Status, e)
			}
		})
	}
}
