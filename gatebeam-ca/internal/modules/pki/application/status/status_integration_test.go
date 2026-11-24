//go:build integration

package status_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	management "gatebeam-ca/internal/modules/pki/application"
	app "gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	pkicrypto "gatebeam-ca/internal/modules/pki/infrastructure/crypto"
	repo "gatebeam-ca/internal/modules/pki/infrastructure/postgres"
	ocsptransport "gatebeam-ca/internal/modules/pki/transport/ocsp"
	"gatebeam-ca/internal/platform/audit"
	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/testkit"
	"gatebeam-ca/internal/platform/transaction"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ocsp"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type security struct {
	tx   transaction.Runner
	deny bool
}

func (s security) Within(ctx context.Context, _ management.ActorRef, fn func(transaction.Scope) error) error {
	if s.deny {
		return management.ErrGrantDenied
	}
	return s.tx.Within(ctx, fn)
}

type fixture struct {
	db      *pgxpool.Pool
	issuer  pkicrypto.Issuer
	signer  *pkicrypto.StatusSigner
	service *app.Service
	admin   *app.Management
	leaf    *x509.Certificate
	key     *ecdsa.PrivateKey
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db := testkit.Postgres(t)
	dir := t.TempDir()
	if e := (pkicrypto.Bootstrapper{}).Generate(ctx, management.BootstrapCommand{RootDirectory: filepath.Join(dir, "offline"), OnlineDirectory: filepath.Join(dir, "online"), RootName: "status root", IntermediateName: "status issuer"}); e != nil {
		t.Fatal(e)
	}
	i, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(dir, "online/issuer.pem"), RootFile: filepath.Join(dir, "online/root.pem"), SignerFile: filepath.Join(dir, "online/issuer.age"), IdentityFile: filepath.Join(dir, "online/identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	r := repo.New()
	tx := postgres.NewRunner(db)
	if e = management.NewRegistry(tx, r).Register(ctx, i.Metadata(), i.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"host.example"}}, k)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := domain.NewPolicy([]string{"host.example"}, domain.ServerAuth)
	serial, e := pkicrypto.NewSerial()
	if e != nil {
		t.Fatal(e)
	}
	// Bootstrap samples issuer NotBefore after key generation. Capture the
	// issuance clock after the issuer exists, including across second boundaries.
	now := time.Now().UTC().Truncate(time.Second)
	der, e := i.SignCSR(csr, p, []string{"host.example"}, serial, now, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey})
	e = tx.Within(ctx, func(sc transaction.Scope) error {
		if e := r.InsertGrant(sc, management.Grant{ID: "grant", Principal: domain.Principal{ID: "principal", Names: []string{"host.example"}, Usage: domain.ServerAuth, Directory: "server", Expires: now.Add(time.Hour)}}); e != nil {
			return e
		}
		if e := r.InsertAccount(sc, domain.Account{ID: "account", PrincipalID: "principal", Directory: "server", Key: pub, Thumbprint: "current-thumb", Status: "valid"}); e != nil {
			return e
		}
		if e := r.InsertOrder(sc, domain.Order{ID: "order", AccountID: "account", Directory: "server", Names: []string{"host.example"}, Usage: domain.ServerAuth, Status: "valid", Expires: now.Add(time.Hour), Revision: 1, Challenges: []domain.Challenge{}}); e != nil {
			return e
		}
		sn := domain.Serial(fmt.Sprintf("%040x", serial))
		if e := r.ReserveSerial(sc, i.Metadata().ID, sn); e != nil {
			return e
		}
		return r.InsertCertificate(sc, domain.IssuedCertificate{OrderID: "order", IssuerID: i.Metadata().ID, Serial: sn, DER: der, Chain: der, NotBefore: now, NotAfter: now.Add(time.Hour)})
	})
	if e != nil {
		t.Fatal(e)
	}
	signer := pkicrypto.NewStatusSigner(i)
	return &fixture{db: db, issuer: i, signer: signer, service: app.New(tx, r, signer, nil), admin: app.NewManagement(security{tx: tx}, r, audit.New(), pkicrypto.Random{}, nil), leaf: leaf, key: k, now: now}
}
func (f *fixture) serial() string { return fmt.Sprintf("%040x", f.leaf.SerialNumber) }
func (f *fixture) id(t *testing.T) app.CertID {
	t.Helper()
	der, e := ocsp.CreateRequest(f.leaf, f.issuer.Certificate, nil)
	if e != nil {
		t.Fatal(e)
	}
	r, e := ocsp.ParseRequest(der)
	if e != nil {
		t.Fatal(e)
	}
	return app.CertID{Hash: r.HashAlgorithm.String(), NameHash: r.IssuerNameHash, KeyHash: r.IssuerKeyHash, Serial: domain.Serial(f.serial())}
}
func statusOf(t *testing.T, f *fixture, id app.CertID) int {
	t.Helper()
	b, e := f.service.OCSP(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	r, e := ocsp.ParseResponse(b, f.issuer.Certificate)
	if e != nil {
		t.Fatal(e)
	}
	return r.Status
}
func TestStatusSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.id(t)
	if statusOf(t, f, id) != ocsp.Good {
		t.Fatal("issued not good")
	}
	if e := f.admin.Revoke(ctx, management.ActorRef{UserID: "admin"}, string(f.issuer.Metadata().ID), f.serial(), 1); e != nil {
		t.Fatal(e)
	}
	if e := f.admin.Revoke(ctx, management.ActorRef{UserID: "admin"}, string(f.issuer.Metadata().ID), f.serial(), 4); !errors.Is(e, domain.ErrAlreadyRevoked) {
		t.Fatal("revocation changed", e)
	}
	if e := postgres.NewRunner(f.db).Within(ctx, func(sc transaction.Scope) error {
		if _, e := repo.New().Principal(sc, "principal"); e != nil {
			return e
		}
		return repo.New().DisablePrincipal(sc, "principal")
	}); e != nil {
		t.Fatal(e)
	}
	// Recreate service, signer and database connections; no security state lives
	// in a process-local map. The new delegated certificate has a new key.
	cfg := f.db.Config()
	fresh, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	f.service = app.New(postgres.NewRunner(fresh), repo.New(), pkicrypto.NewStatusSigner(f.issuer), nil)
	if statusOf(t, f, id) != ocsp.Revoked {
		t.Fatal("restart lost revocation")
	}
	var disabled bool
	if e = fresh.QueryRow(ctx, "SELECT disabled FROM pki_principals WHERE id='principal'").Scan(&disabled); e != nil || !disabled {
		t.Fatal("restart lost disable", e)
	}
	unknown := id
	unknown.Serial = "000000000000000000000000000000000000007f"
	if statusOf(t, f, unknown) != ocsp.Unknown {
		t.Fatal("unknown became good")
	}
	wrong := id
	wrong.KeyHash = append([]byte(nil), id.KeyHash...)
	wrong.KeyHash[0] ^= 1
	if _, e = f.service.OCSP(ctx, wrong); !errors.Is(e, app.ErrUnknownIssuer) {
		t.Fatal("wrong issuer became good", e)
	}
	var credentials int
	if e = fresh.QueryRow(ctx, "SELECT count(*) FROM pki_status_certificates").Scan(&credentials); e != nil || credentials != 2 {
		t.Fatal("delegated credentials not reserved", credentials, e)
	}
}
func TestStatusOCSPStandardGETPOSTAndCRL(t *testing.T) {
	f := newFixture(t)
	handler := ocsptransport.New(f.service)
	der, e := ocsp.CreateRequest(f.leaf, f.issuer.Certificate, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, method := range []string{"GET", "POST"} {
		path := "/ocsp"
		if method == "GET" {
			path += "/" + base64.StdEncoding.EncodeToString(der)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(der))
		r.Header.Set("Content-Type", "application/ocsp-request")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		response, e := ocsp.ParseResponse(w.Body.Bytes(), f.issuer.Certificate)
		if e != nil || w.Code != 200 || response.Status != ocsp.Good {
			t.Fatal("standard OCSP", method, w.Code, e)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "/ocsp/bad", bytes.NewReader([]byte("bad")))
		r.Header.Set("Content-Type", "application/ocsp-request")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if bytes.Equal(w.Body.Bytes(), der) || w.Code == 200 {
			t.Fatal("malformed accepted")
		}
	}
	before, e := f.service.CRL(context.Background(), f.issuer.Metadata().ID)
	if e != nil {
		t.Fatal(e)
	}
	a, e := x509.ParseRevocationList(before)
	if e != nil || a.CheckSignatureFrom(f.issuer.Certificate) != nil {
		t.Fatal("CRL invalid", e)
	}
	if e = f.admin.Revoke(context.Background(), management.ActorRef{UserID: "admin"}, string(f.issuer.Metadata().ID), f.serial(), 1); e != nil {
		t.Fatal(e)
	}
	after, e := f.service.CRL(context.Background(), f.issuer.Metadata().ID)
	if e != nil {
		t.Fatal(e)
	}
	b, e := x509.ParseRevocationList(after)
	if e != nil || b.CheckSignatureFrom(f.issuer.Certificate) != nil || b.Number.Cmp(a.Number) <= 0 || len(b.RevokedCertificateEntries) != 1 || b.RevokedCertificateEntries[0].SerialNumber.Cmp(f.leaf.SerialNumber) != 0 {
		t.Fatal("CRL missing current revocation", e)
	}
}
func TestRevocationRollsBackOnAuditFailure(t *testing.T) {
	f := newFixture(t)
	tx := postgres.NewRunner(f.db)
	denied := app.NewManagement(security{tx: tx, deny: true}, repo.New(), audit.New(), pkicrypto.Random{}, nil)
	if e := denied.Revoke(context.Background(), management.ActorRef{}, string(f.issuer.Metadata().ID), f.serial(), 1); !errors.Is(e, management.ErrGrantDenied) {
		t.Fatal(e)
	}
	broken := app.NewManagement(security{tx: tx}, repo.New(), failingAudit{}, pkicrypto.Random{}, nil)
	if e := broken.Revoke(context.Background(), management.ActorRef{}, string(f.issuer.Metadata().ID), f.serial(), 1); e == nil {
		t.Fatal("audit failure succeeded")
	}
	if statusOf(t, f, f.id(t)) != ocsp.Good {
		t.Fatal("rollback persisted revocation")
	}
}

type failingAudit struct{}

func (failingAudit) Append(transaction.Scope, audit.Event) error {
	return errors.New("audit unavailable")
}
func TestRevokeCertificateCurrentAuthorityAndCertificateKey(t *testing.T) {
	for _, kind := range []string{"account", "stale", "wrong-key", "certificate-key-disabled", "wrong-directory"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			in := app.Request{Directory: "server", Certificate: f.leaf.Raw, Reason: 1, AccountID: "account", Thumbprint: "current-thumb"}
			switch kind {
			case "stale":
				in.Thumbprint = "old-thumb"
			case "wrong-directory":
				in.Directory = "client"
			case "wrong-key":
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				in.Key, _ = json.Marshal(jose.JSONWebKey{Key: &k.PublicKey})
				in.AccountID = ""
			case "certificate-key-disabled":
				in.AccountID = ""
				in.Key, _ = json.Marshal(jose.JSONWebKey{Key: &f.key.PublicKey})
				if _, e := f.db.Exec(ctx, "UPDATE pki_principals SET disabled=true WHERE id='principal'"); e != nil {
					t.Fatal(e)
				}
			}
			e := f.service.RevokeCertificate(ctx, in)
			valid := kind == "account" || kind == "certificate-key-disabled"
			if valid && e != nil {
				t.Fatal(e)
			}
			if !valid && e == nil {
				t.Fatal("unauthorized revoke succeeded")
			}
		})
	}
}

func TestRevokeCertOtherAccountRequiresEveryCurrentAuthorization(t *testing.T) {
	for _, state := range []string{"valid", "pending", "expired", "grant-shrunk"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			r := repo.New()
			tx := postgres.NewRunner(f.db)
			now := time.Now().UTC()
			names := []string{"host.example"}
			if state == "grant-shrunk" {
				names = []string{"other.example"}
			}
			e := tx.Within(ctx, func(sc transaction.Scope) error {
				if e := r.InsertGrant(sc, management.Grant{ID: "other", Principal: domain.Principal{ID: "other", Names: names, Usage: domain.ServerAuth, Directory: "server", Expires: now.Add(time.Hour)}}); e != nil {
					return e
				}
				if e := r.InsertAccount(sc, domain.Account{ID: "other", PrincipalID: "other", Directory: "server", Key: []byte("public"), Thumbprint: "other-current", Status: "valid"}); e != nil {
					return e
				}
				expires := now.Add(time.Hour)
				challengeState := "valid"
				if state == "expired" {
					expires = now.Add(-time.Hour)
				}
				if state == "pending" {
					challengeState = "pending"
				}
				return r.InsertOrder(sc, domain.Order{ID: "other", AccountID: "other", Directory: "server", Names: []string{"host.example"}, Usage: domain.ServerAuth, Status: "ready", Expires: expires, Revision: 1, Challenges: []domain.Challenge{{ID: "proof", Name: "host.example", Token: "proof", Status: challengeState, Validated: now}}})
			})
			if e != nil {
				t.Fatal(e)
			}
			e = f.service.RevokeCertificate(ctx, app.Request{Directory: "server", Certificate: f.leaf.Raw, Reason: 1, AccountID: "other", Thumbprint: "other-current"})
			if state == "valid" && e != nil {
				t.Fatal("all identifier authorizations refused", e)
			}
			if state != "valid" && e == nil {
				t.Fatal("invalid authorization accepted", state)
			}
		})
	}
}

func TestRevocationRestrictedManagementRoleNeedsNoDEROrSigner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	role := fmt.Sprintf("p4_management_%d", time.Now().UnixNano())
	var schema string
	if e := f.db.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	if _, e := f.db.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD 'test-only'"); e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, q := range []string{"DROP OWNED BY " + role, "DROP ROLE " + role} {
			if _, e := f.db.Exec(ctx, q); e != nil {
				t.Error(e)
			}
		}
	}()
	for _, q := range []string{"GRANT USAGE ON SCHEMA " + schema + " TO " + role, "GRANT SELECT ON pki_principals,pki_accounts TO " + role, "GRANT SELECT(order_id,issuer_id,serial,not_before,not_after) ON pki_certificates TO " + role, "GRANT SELECT(id,account_id,names) ON pki_orders TO " + role, "GRANT SELECT,INSERT ON pki_revocations TO " + role, "GRANT INSERT ON audit TO " + role} {
		if _, e := f.db.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	cfg := f.db.Config().Copy()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "test-only"
	login, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer login.Close()
	admin := app.NewManagement(security{tx: postgres.NewRunner(login)}, repo.New(), audit.New(), pkicrypto.Random{}, nil)
	if e = admin.Revoke(ctx, management.ActorRef{UserID: "admin"}, string(f.issuer.Metadata().ID), f.serial(), 1); e != nil {
		t.Fatal("restricted API could not commit", e)
	}
	for _, q := range []string{"SELECT der FROM pki_certificates", "UPDATE pki_certificates SET der='forged'", "UPDATE pki_revocations SET reason=4", "DELETE FROM pki_revocations", "TRUNCATE pki_revocations"} {
		if _, e = login.Exec(ctx, q); e == nil {
			t.Fatal("API exceeded authority", q)
		}
	}
	for _, q := range []string{"UPDATE pki_revocations SET reason=4", "DELETE FROM pki_revocations"} {
		if _, e = f.db.Exec(ctx, q); e == nil {
			t.Fatal("immutable trigger allowed rollback", q)
		}
	}
	if statusOf(t, f, f.id(t)) != ocsp.Revoked {
		t.Fatal("restricted API did not persist status")
	}
}
