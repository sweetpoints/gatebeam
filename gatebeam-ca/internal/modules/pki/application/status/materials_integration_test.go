//go:build integration

package status_test

import (
	"crypto/sha256"
	"encoding/hex"
	management "gatebeam-ca/internal/modules/pki/application"
	app "gatebeam-ca/internal/modules/pki/application/status"
	repo "gatebeam-ca/internal/modules/pki/infrastructure/postgres"
	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/transaction"
	"strings"
	"testing"
	"time"
)

func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func TestCurrentMaterialStatusIdentityAndRevocationFence(t *testing.T) {
	f := newFixture(t)
	tx := postgres.NewRunner(f.db)
	owner := app.NewMaterials(repo.New())
	leaf := app.LeafIdentity{IssuerKey: digest(f.issuer.Certificate.RawSubjectPublicKeyInfo), Serial: f.serial(), DERDigest: digest(f.leaf.Raw), Managed: true}
	check := func(v app.LeafIdentity) error {
		return tx.Within(t.Context(), func(sc transaction.Scope) error { return owner.ValidateWithin(sc, v) })
	}
	if err := check(leaf); err != nil {
		t.Fatal("known good", err)
	}
	for _, mutate := range []func(*app.LeafIdentity){func(v *app.LeafIdentity) { v.IssuerKey = strings.Repeat("a", 64) }, func(v *app.LeafIdentity) { v.Serial = strings.Repeat("0", 39) + "1" }, func(v *app.LeafIdentity) { v.DERDigest = strings.Repeat("b", 64) }} {
		bad := leaf
		mutate(&bad)
		if err := check(bad); err == nil {
			t.Fatal("wrong key/serial/DER accepted")
		}
	}
	external := leaf
	external.Managed = false
	external.IssuerKey = strings.Repeat("a", 64)
	if err := check(external); err != nil {
		t.Fatal("external CA forced into local ledger", err)
	}
	// A current material decision holds a shared fence until its transaction ends.
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- tx.Within(t.Context(), func(sc transaction.Scope) error {
			if err := owner.ValidateWithin(sc, leaf); err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	revoked := make(chan error, 1)
	go func() {
		revoked <- f.admin.Revoke(t.Context(), management.ActorRef{UserID: "operator"}, string(f.issuer.Metadata().ID), f.serial(), 1)
	}()
	select {
	case err := <-revoked:
		close(release)
		t.Fatal("revocation crossed material receipt fence", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := check(leaf); err == nil {
		t.Fatal("committed revocation ignored")
	}
	leaf.Managed = false
	if err := check(leaf); err == nil {
		t.Fatal("import marker bypassed local revocation")
	}
}
func TestMaterialStatusQuarantineAndLegacyIssuerRefresh(t *testing.T) {
	f := newFixture(t)
	tx := postgres.NewRunner(f.db)
	owner := app.NewMaterials(repo.New())
	leaf := app.LeafIdentity{IssuerKey: digest(f.issuer.Certificate.RawSubjectPublicKeyInfo), Serial: f.serial(), DERDigest: digest(f.leaf.Raw), Managed: true}
	if _, err := f.db.Exec(t.Context(), `INSERT INTO pki_issuers(id,fingerprint,certificate_der,not_before,not_after) VALUES('retired',$1,$2,$3,$4)`, digest(f.issuer.Chain[len(f.issuer.Chain)-1].Raw), f.issuer.Chain[len(f.issuer.Chain)-1].Raw, f.issuer.Certificate.NotBefore, f.issuer.Certificate.NotAfter); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		return tx.Within(t.Context(), func(sc transaction.Scope) error { return owner.ValidateWithin(sc, leaf) })
	}
	if err := check(); err == nil {
		t.Fatal("unclassified historical issuer accepted")
	}
	if err := management.NewRegistry(tx, repo.New()).Register(t.Context(), f.issuer.Metadata(), f.issuer.Certificate.Raw); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatal("retired public metadata not refreshed", err)
	}
	if err := tx.Within(t.Context(), func(sc transaction.Scope) error { return repo.New().QuarantineRecovery(sc) }); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("quarantined issuer accepted")
	}
}
