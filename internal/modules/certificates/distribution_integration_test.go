//go:build integration

package certificates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"gatebeam/internal/integration/certificatematerials"
	cert "gatebeam/internal/modules/certificates/application"
	certdomain "gatebeam/internal/modules/certificates/domain"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	nodes "gatebeam/internal/modules/deployment/application/nodes"
	deploypg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	fixture "gatebeam/tests/fixtures/deployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type distributionLeafStatus struct{ revoked bool }

func (s *distributionLeafStatus) ValidateLeafWithin(transaction.Scope, cert.StoredVersion, bool) error {
	if s.revoked {
		return certdomain.ErrUnavailable
	}
	return nil
}
func TestBothNodesReceiveAuthorizedCertificateVersion(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(p)
	capabilities := fixture.ApplyRoles(t, p, strings.ReplaceAll(uuid.NewString(), "-", "")[:12])
	type node struct {
		binding cert.RecipientBinding
		key     *secrets.Store
		runner  transaction.Runner
	}
	makeNode := func() node {
		file := filepath.Join(t.TempDir(), "identity")
		if e := secrets.EnsureIdentity(file); e != nil {
			t.Fatal(e)
		}
		key, e := secrets.New(file)
		if e != nil {
			t.Fatal(e)
		}
		ref := cert.NodeRef{ID: uuid.NewString(), Epoch: 1}
		principal := "node_" + uuid.NewString()[:8]
		quoted := pgx.Identifier{principal}.Sanitize()
		var schema string
		if e := p.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); e != nil {
			t.Fatal(e)
		}
		if _, e = p.Exec(ctx, `CREATE ROLE `+quoted+` LOGIN PASSWORD 'fixture-only';GRANT `+pgx.Identifier{capabilities["gatebeam_runtime_edge"]}.Sanitize()+` TO `+quoted+`;GRANT USAGE ON SCHEMA `+pgx.Identifier{schema}.Sanitize()+` TO `+quoted); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP OWNED BY `+quoted+`;DROP ROLE `+quoted) })
		cfg := p.Config().Copy()
		cfg.ConnConfig.User = principal
		cfg.ConnConfig.Password = "fixture-only"
		peer, e := pgxpool.NewWithConfig(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(peer.Close)
		registration, _ := json.Marshal(nodes.NodeRegistration{EncryptionRecipients: map[string]string{"leaf": key.Recipient()}})
		_, e = p.Exec(ctx, `INSERT INTO deployment_nodes(id,epoch,principal,registration) VALUES($1,1,$2,$3)`, ref.ID, principal, registration)
		if e != nil {
			t.Fatal(e)
		}
		return node{cert.RecipientBinding{Node: ref, Recipient: key.Recipient()}, key, postgres.NewRunner(peer)}
	}
	a, b := makeNode(), makeNode()
	specID, versionID := uuid.NewString(), uuid.NewString()
	a.binding.VersionID = versionID
	b.binding.VersionID = versionID
	keyPEM := []byte("owned fixture private key")
	cipher, e := a.key.Seal("certificates/version/"+versionID, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	v := cert.Version{ID: versionID, SpecID: specID, SpecRevision: 1, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	body, _ := json.Marshal(v)
	for _, q := range []string{`INSERT INTO certificates_resources(kind,id,revision,enabled) VALUES('spec',$1,1,true)`, `INSERT INTO certificates_revisions(kind,id,revision,body) VALUES('spec',$1,1,'{}')`} {
		if _, e = p.Exec(ctx, q, specID); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = p.Exec(ctx, `INSERT INTO certificates_versions(id,spec_id,spec_revision,body,certificate_pem,encrypted_key) VALUES($1,$2,1,$3,'certificate',$4)`, versionID, specID, body, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO certificates_attempts(spec_id,spec_revision,current_version) VALUES($1,1,$2)`, specID, versionID); e != nil {
		t.Fatal(e)
	}
	authority := certificatematerials.NodeAuthority{Nodes: nodes.New(deploypg.New(), time.Now)}
	status := &distributionLeafStatus{}
	owner := cert.NewDistribution(certpg.NewDistribution(), authority, a.key, certcrypto.Crypto{}, time.Now)
	owner.SetLeafStatus(status)
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return owner.RewrapWithin(sc, versionID, []cert.RecipientBinding{a.binding, b.binding})
	}); e != nil {
		t.Fatal(e)
	}
	var learnedByB []byte
	for _, n := range []node{a, b} {
		var envelope []byte
		if e := n.runner.Within(ctx, func(sc transaction.Scope) (e error) { envelope, e = owner.EnvelopeWithin(sc, n.binding); return }); e != nil {
			t.Fatal(e)
		}
		if n.binding.Node == b.binding.Node {
			learnedByB = append([]byte{}, envelope...)
		}
		got, e := n.key.Open("certificates/version/"+versionID, envelope)
		if e != nil || !bytes.Equal(got, keyPEM) {
			t.Fatalf("own node decrypt: %v", e)
		}
	}
	status.revoked = true
	if e := a.runner.Within(ctx, func(sc transaction.Scope) error { _, e := owner.EnvelopeWithin(sc, a.binding); return e }); e == nil {
		t.Fatal("revoked certificate version distributed")
	}
	status.revoked = false
	forged := b.binding
	forged.Recipient = a.key.Recipient()
	if e := tx.Within(ctx, func(sc transaction.Scope) error { _, e := owner.EnvelopeWithin(sc, forged); return e }); e == nil {
		t.Fatal("unregistered recipient accepted")
	}
	if _, e = p.Exec(ctx, `UPDATE deployment_nodes SET state='revoked' WHERE id=$1`, b.binding.Node.ID); e != nil {
		t.Fatal(e)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error { _, e := owner.EnvelopeWithin(sc, b.binding); return e }); e == nil {
		t.Fatal("revoked node fetched new envelope")
	}
	if got, e := b.key.Open("certificates/version/"+versionID, learnedByB); e != nil || !bytes.Equal(got, keyPEM) {
		t.Fatal("test incorrectly assumed node revocation erased a previously learned key")
	}
	// Previously learned plaintext cannot be revoked by deleting envelopes. The
	// security response must issue a new leaf key/version for the surviving nodes.
	if _, e := b.key.Open("certificates/version/"+versionID, cipher); e == nil {
		t.Fatal("legacy owner ciphertext unexpectedly shared")
	}
}
