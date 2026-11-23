//go:build integration

package backup_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gatebeam/internal/integration/recovery"
	backup "gatebeam/internal/modules/backup/application"
	pki "gatebeam/internal/modules/pki/application"
	status "gatebeam/internal/modules/pki/application/status"
	domain "gatebeam/internal/modules/pki/domain"
	crypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotRestoresPublicLeafStatusAndQuarantine(t *testing.T) {
	snapshot, key, p := fixture(t)
	ctx := t.Context()
	root := t.TempDir()
	if e := (crypto.Bootstrapper{}).Generate(ctx, pki.BootstrapCommand{RootDirectory: filepath.Join(root, "offline"), OnlineDirectory: filepath.Join(root, "online"), RootName: "recovery root", IntermediateName: "recovery issuer"}); e != nil {
		t.Fatal(e)
	}
	issuer, e := crypto.LoadIssuer(crypto.Config{CertificateFile: filepath.Join(root, "online/issuer.pem"), RootFile: filepath.Join(root, "online/root.pem"), SignerFile: filepath.Join(root, "online/issuer.age"), IdentityFile: filepath.Join(root, "online/identity.agekey")})
	if e != nil {
		t.Fatal(e)
	}
	tx := postgres.NewRunner(p)
	store := repo.New()
	if e = pki.NewRegistry(tx, store).Register(ctx, issuer.Metadata(), issuer.Certificate.Raw); e != nil {
		t.Fatal(e)
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(71), DNSNames: []string{"recovery.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, issuer.Certificate, &leafKey.PublicKey, issuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	serial := domain.Serial(fmt.Sprintf("%040x", leaf.SerialNumber))
	e = tx.Within(ctx, func(sc transaction.Scope) error {
		if e := store.InsertGrant(sc, pki.Grant{ID: "recovery-grant", Principal: domain.Principal{ID: "recovery-principal", Names: leaf.DNSNames, Usage: domain.ServerAuth, Directory: "server", Expires: now.Add(time.Hour)}}); e != nil {
			return e
		}
		if e := store.InsertAccount(sc, domain.Account{ID: "recovery-account", PrincipalID: "recovery-principal", Directory: "server", Key: json.RawMessage(`{}`), Thumbprint: "recovery", Status: "valid"}); e != nil {
			return e
		}
		if e := store.InsertOrder(sc, domain.Order{ID: "recovery-order", AccountID: "recovery-account", Directory: "server", Names: leaf.DNSNames, Usage: domain.ServerAuth, Status: "valid", Revision: 1, Expires: now.Add(time.Hour), Challenges: []domain.Challenge{}}); e != nil {
			return e
		}
		if e := store.ReserveSerial(sc, issuer.Metadata().ID, serial); e != nil {
			return e
		}
		return store.InsertCertificate(sc, domain.IssuedCertificate{OrderID: "recovery-order", IssuerID: issuer.Metadata().ID, Serial: serial, DER: der, Chain: der, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter})
	})
	if e != nil {
		t.Fatal(e)
	}
	hash := func(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
	identity := status.LeafIdentity{IssuerKey: hash(issuer.Certificate.RawSubjectPublicKeyInfo), Serial: string(serial), DERDigest: hash(der), Managed: true}
	if e = tx.Within(ctx, func(sc transaction.Scope) error { return status.NewMaterials(store).ValidateWithin(sc, identity) }); e != nil {
		t.Fatal("positive source status", e)
	}
	artifact := create(t, snapshot)
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	restorer := backup.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	report, e := restorer.Verify(ctx, artifact.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = restorer.Restore(ctx, report, backup.Conservative); e != nil {
		t.Fatal(e)
	}
	defer p.Exec(ctx, `DROP DATABASE `+target.Database+` WITH (FORCE)`)
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = target.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	var fingerprint, state string
	if e = restored.QueryRow(ctx, `SELECT issuer_key_fingerprint,state FROM pki_leaf_status WHERE serial=$1`, string(serial)).Scan(&fingerprint, &state); e != nil || fingerprint != identity.IssuerKey || state != "quarantined" {
		t.Fatal("restored projection lost current security", fingerprint, state, e)
	}
	for _, managed := range []bool{true, false} {
		identity.Managed = managed
		if e = postgres.NewRunner(restored).Within(ctx, func(sc transaction.Scope) error { return status.NewMaterials(store).ValidateWithin(sc, identity) }); e == nil {
			t.Fatal("restored managed/imported local credential revived")
		}
	}
}
