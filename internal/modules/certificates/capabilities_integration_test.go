//go:build integration

package certificates_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/modules/certificates"
	app "gatebeam/internal/modules/certificates/application"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	pkistatus "gatebeam/internal/modules/pki/application/status"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	deploymentfixture "gatebeam/tests/fixtures/deployment"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type capabilityGuard struct{ tx transaction.Runner }

func (g capabilityGuard) Within(ctx context.Context, _ app.ActorRef, fn func(transaction.Scope) error) error {
	return g.tx.Within(ctx, fn)
}
func (capabilityGuard) GuardWithin(transaction.Scope) error                           { return nil }
func (capabilityGuard) RequireWithin(transaction.Scope, app.ActorRef, []string) error { return nil }
func leafFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned capability root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(rootDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"imported.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
func TestEdgeRoleAndKeysCannotOpenProviderSecrets(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(p)
	guard := capabilityGuard{tx}
	leafFile := filepath.Join(t.TempDir(), "leaf.agekey")
	providerFile := filepath.Join(t.TempDir(), "provider.agekey")
	for _, path := range []string{leafFile, providerFile} {
		if e := secrets.EnsureIdentity(path); e != nil {
			t.Fatal(e)
		}
	}
	leaf, e := secrets.New(leafFile)
	if e != nil {
		t.Fatal(e)
	}
	provider, e := secrets.New(providerFile)
	if e != nil {
		t.Fatal(e)
	}
	// API assembly is seal-only for both independent recipients.
	leafPublic, e := secrets.NewRecipient(leaf.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := any(leafPublic).(interface {
		Open(string, []byte) ([]byte, error)
	}); ok {
		t.Fatal("API recipient has decrypt capability")
	}
	manager, imports, e := certificates.NewManagement(p, guard, guard, leaf.Recipient(), provider.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	account, e := manager.SaveAccount(ctx, app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "google", Email: "owned@example.test", EABKeyID: "owned-id"}, []byte("owned-eab-hmac"))
	if e != nil {
		t.Fatal(e)
	}
	credential, e := manager.SaveCredential(ctx, app.ActorRef{}, "", 0, app.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "imported.test"}, []byte("owned-cloudflare-token"))
	if e != nil {
		t.Fatal(e)
	}
	spec, e := manager.SaveSpec(ctx, app.ActorRef{}, "", 0, app.Spec{Names: []string{"imported.test"}, Purpose: "serverAuth", Method: "import"})
	if e != nil {
		t.Fatal(e)
	}
	cert, key := leafFixture(t)
	version, e := imports.Import(ctx, app.ActorRef{}, spec.ID, cert, key)
	if e != nil {
		t.Fatal(e)
	}
	repo := certpg.New()
	for _, resource := range []app.Resource{account, credential} {
		if e = tx.Within(ctx, func(sc transaction.Scope) error {
			record, e := repo.Read(sc, resource.Kind, resource.ID, 1)
			if e != nil {
				return e
			}
			labelJSON, _ := json.Marshal([]any{resource.Kind, resource.ID, int64(1)})
			label := "certificates/" + string(labelJSON)
			// Even an independently obtained ciphertext cannot be decrypted by edge.
			if _, e = leaf.Open(label, record.Secret); e == nil {
				t.Fatal("edge decrypted provider secret", resource.Kind)
			}
			plain, e := provider.Open(label, record.Secret)
			if e != nil {
				return e
			}
			defer clear(plain)
			if resource.Kind == "account" {
				var payload struct{ Key, EAB []byte }
				if json.Unmarshal(plain, &payload) != nil || len(payload.Key) == 0 || string(payload.EAB) != "owned-eab-hmac" {
					t.Fatal("worker account/EAB unavailable")
				}
			} else if string(plain) != "owned-cloudflare-token" {
				t.Fatal("worker CF credential unavailable")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	schema := p.Config().ConnConfig.RuntimeParams["search_path"]
	suffix := strings.TrimPrefix(schema, "test_")
	allRoles := deploymentfixture.ApplyRoles(t, p, suffix)
	roles := map[string]string{"management": allRoles["gatebeam_certificates_management"], "worker": allRoles["gatebeam_certificates_worker"], "edge": allRoles["gatebeam_certificates_edge"]}
	if _, e = p.Exec(ctx, "GRANT SELECT ON pki_leaf_status TO "+pgx.Identifier{roles["edge"]}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	rolePool := func(kind string) *pgxpool.Pool {
		name := roles[kind]
		if _, e = p.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		cfg := p.Config().Copy()
		cfg.AfterConnect = func(c context.Context, conn *pgx.Conn) error {
			_, e := conn.Exec(c, "SET ROLE "+pgx.Identifier{name}.Sanitize())
			return e
		}
		pool, e := pgxpool.NewWithConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	edgePool := rolePool("edge")
	workerPool := rolePool("worker")
	var cipher []byte
	if e = edgePool.QueryRow(ctx, "SELECT secret FROM certificates_revisions WHERE kind='credential' AND id=$1", credential.ID).Scan(&cipher); e == nil {
		t.Fatal("edge SQL role read provider ciphertext")
	}
	if e = workerPool.QueryRow(ctx, "SELECT secret FROM certificates_revisions WHERE kind='credential' AND id=$1", credential.ID).Scan(&cipher); e != nil {
		t.Fatal("worker SQL role denied credential", e)
	}
	edge, e := certificates.NewEdge(edgePool, guard, leafFile, provider.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	edge.SetLeafStatus(certificatematerials.LeafStatus{Owner: pkistatus.NewMaterials(pkipg.New())})
	refs := []app.MaterialRef{{Kind: "certificate", ID: spec.ID, Revision: 1, Names: []string{"imported.test"}, Purpose: "serverAuth"}}
	if e = postgres.NewRunner(edgePool).Within(ctx, func(sc transaction.Scope) error {
		materials, e := edge.ReadMaterialsWithin(sc, refs)
		if e != nil {
			return e
		}
		if len(materials.Items) != 1 || materials.Items[0].Version.ID != version.ID || !bytes.Equal(materials.Items[0].KeyPEM, key) {
			t.Fatal("edge lost leaf access")
		}
		clear(materials.Items[0].KeyPEM)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = tx.Within(ctx, func(sc transaction.Scope) error { _, e := imports.ReadMaterialsWithin(sc, refs); return e }); e == nil {
		t.Fatal("API import assembly acquired leaf decryption")
	}
	worker, e := certificates.NewWorker(workerPool, guard, providerFile, leaf.Recipient(), "")
	if e != nil {
		t.Fatal(e)
	}
	if e = worker.PrepareCurrent(ctx); e != nil {
		t.Fatal("worker owning preparation role", e)
	}
	if e = postgres.NewRunner(workerPool).Within(ctx, func(sc transaction.Scope) error { _, e := worker.ReadMaterialsWithin(sc, refs); return e }); e == nil {
		t.Fatal("worker acquired leaf private-key decryption")
	}
}
