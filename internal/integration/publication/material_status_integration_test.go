//go:build integration

package publication_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/integration/certificateaccess"
	"gatebeam/internal/integration/certificatematerials"
	pub "gatebeam/internal/integration/publication"
	cert "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	deploy "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	dd "gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	id "gatebeam/internal/modules/ingress/domain"
	pki "gatebeam/internal/modules/pki/application"
	status "gatebeam/internal/modules/pki/application/status"
	pkid "gatebeam/internal/modules/pki/domain"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/transaction"
	"math/big"
	"testing"
	"time"
)

type fixturePlainSecrets struct{}

func (fixturePlainSecrets) Seal(_ string, b []byte) ([]byte, error) {
	return append([]byte{}, b...), nil
}
func (fixturePlainSecrets) Open(_ string, b []byte) ([]byte, error) {
	return append([]byte{}, b...), nil
}

type statusSecurity struct{ transaction.Runner }

func (s statusSecurity) Within(ctx context.Context, _ pki.ActorRef, fn func(transaction.Scope) error) error {
	return s.Runner.Within(ctx, fn)
}

type boundMaterials struct{ certificatematerials.Adapter }

func (s boundMaterials) ReadWithin(sc transaction.Scope, snapshot deploy.Snapshot) (edge.RuntimeState, error) {
	return s.BindWithin(sc, snapshot, edge.RuntimeState{Generation: "base", Now: time.Now()})
}

type materialFixture struct {
	f       *fixture
	service *cert.Service
	spec    cert.Record
	policy  cert.Spec
	issuer  pkicrypto.Issuer
	version cert.Version
	serial  int64
}

func newMaterialFixture(t *testing.T) *materialFixture {
	f := setup(t)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned material issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	issuer := pkicrypto.Issuer{Certificate: root, Signer: key}
	repo := pkipg.New()
	if e = pki.NewRegistry(f.tx, repo).Register(t.Context(), issuer.Metadata(), der); e != nil {
		t.Fatal(e)
	}
	trustID, _ := f.ids.NewID()
	specID, _ := f.ids.NewID()
	accountID, _ := f.ids.NewID()
	policy := cert.Spec{Names: []string{"material.example.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: accountID, Challenge: "http-01", TrustID: trustID, TrustRevision: 1}
	body, _ := json.Marshal(policy)
	spec := cert.Record{Resource: cert.Resource{ID: specID, Kind: "spec", Revision: 1, Enabled: true, Body: body}}
	trustBody, _ := json.Marshal(cert.TrustBundle{Purpose: "serverAuth", Fingerprints: []string{issuer.Metadata().Fingerprint}})
	if e = f.tx.Within(t.Context(), func(sc transaction.Scope) error {
		if e := repo.InsertGrant(sc, pki.Grant{ID: "grant", Principal: pkid.Principal{ID: "principal", Names: policy.Names, Usage: pkid.ServerAuth, Directory: "server", Expires: now.Add(time.Hour)}}); e != nil {
			return e
		}
		if e := repo.InsertAccount(sc, pkid.Account{ID: "account", PrincipalID: "principal", Directory: "server", Key: json.RawMessage(`{}`), Thumbprint: "thumb", Status: "valid"}); e != nil {
			return e
		}
		if e := certpg.New().Save(sc, cert.Record{Resource: cert.Resource{ID: trustID, Kind: "trust", Revision: 1, Enabled: true, Body: trustBody}, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, 0); e != nil {
			return e
		}
		return certpg.New().Save(sc, spec, 0)
	}); e != nil {
		t.Fatal(e)
	}
	service := cert.New(f.tx, certpg.New(), nil, certcrypto.Crypto{}, fixturePlainSecrets{}, nil, nil)
	service.SetLeafStatus(certificatematerials.LeafStatus{Owner: status.NewMaterials(repo)})
	m := &materialFixture{f: f, service: service, spec: spec, policy: policy, issuer: issuer}
	m.replace(t)
	adapter := certificatematerials.Adapter{Owner: service}
	f.pub = f.coordinator(adapter, jobs.New(f.p), audit.New())
	return m
}
func (m *materialFixture) replace(t *testing.T) {
	m.serial++
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(100 + m.serial), DNSNames: m.policy.Names, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, m.issuer.Certificate, &key.PublicKey, m.issuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.issuer.Certificate.Raw})...)
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	v, e := (certcrypto.Crypto{}).Inspect(m.policy, chain, keyPEM, now, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.issuer.Certificate.Raw}))
	if e != nil {
		t.Fatal(e)
	}
	v.ID, _ = m.f.ids.NewID()
	v.SpecID = m.spec.ID
	v.SpecRevision = 1
	v.EnrollmentProvider = "internal-server"
	e = m.f.tx.Within(t.Context(), func(sc transaction.Scope) error {
		r := pkipg.New()
		order := fmt.Sprintf("order-%d", m.serial)
		serial := pkid.Serial(v.Serial)
		if e := r.InsertOrder(sc, pkid.Order{ID: order, AccountID: "account", Directory: "server", Names: m.policy.Names, Usage: pkid.ServerAuth, Status: "valid", Expires: now.Add(time.Hour), Revision: 1, Challenges: []pkid.Challenge{}}); e != nil {
			return e
		}
		if e := r.ReserveSerial(sc, m.issuer.Metadata().ID, serial); e != nil {
			return e
		}
		if e := r.InsertCertificate(sc, pkid.IssuedCertificate{OrderID: order, IssuerID: m.issuer.Metadata().ID, Serial: serial, DER: der, Chain: der, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}); e != nil {
			return e
		}
		cr := certpg.New()
		attempt, e := cr.Claim(sc, m.spec.ID, 1, v.ID, now.Add(time.Minute))
		if e != nil {
			return e
		}
		return cr.Commit(sc, cert.Work{Spec: m.spec, Token: v.ID, Attempt: attempt}, cert.StoredVersion{Version: v, CertificatePEM: chain, EncryptedKey: keyPEM})
	})
	if e != nil {
		t.Fatal(e)
	}
	m.version = v
}
func (m *materialFixture) revoke(t *testing.T) {
	t.Helper()
	if e := status.NewManagement(statusSecurity{m.f.tx}, pkipg.New(), audit.New(), pkicrypto.Random{}, nil).Revoke(t.Context(), pki.ActorRef{UserID: "operator"}, string(m.issuer.Metadata().ID), m.version.Serial, 1); e != nil {
		t.Fatal(e)
	}
}
func (m *materialFixture) execution(t *testing.T, s id.Site) (*pub.Execution, pub.CandidateView, edge.Plan) {
	t.Helper()
	f := m.f
	c := f.prepare(t, f.admin, []string{s.ID}, selected(s))
	if _, e := f.pub.Publish(t.Context(), f.admin, c.ID); e != nil {
		t.Fatal(e)
	}
	queue := jobs.New(f.p)
	job, e := queue.ClaimKinds(t.Context(), "edge", time.Minute, []string{"deployment.apply"})
	if e != nil {
		t.Fatal(e)
	}
	ex := pub.NewExecution(f.pub, queue, job, boundMaterials{certificatematerials.Adapter{Owner: m.service}}, nginx.Compiler{})
	plan, e := ex.Prepare(t.Context(), c.ID)
	if e != nil {
		t.Fatal(e)
	}
	return ex, c, plan
}

type materialDisk struct{ j dd.ApplyJournal }

func (d *materialDisk) Lock(context.Context) (func(), error)                     { return func() {}, nil }
func (d *materialDisk) Stage(_ context.Context, a edge.Artifact) (string, error) { return a.ID, nil }
func (d *materialDisk) Switch(context.Context, string) error                     { return nil }
func (d *materialDisk) Load(context.Context) (dd.ApplyJournal, error)            { return d.j, nil }
func (d *materialDisk) Save(_ context.Context, j dd.ApplyJournal) error          { d.j = j; return nil }

type materialProcess struct {
	version     string
	activations int
}

func (p *materialProcess) Validate(context.Context, string) error { return nil }
func (p *materialProcess) Activate(_ context.Context, v string) error {
	p.version = v
	p.activations++
	return nil
}
func (p *materialProcess) Observe(context.Context) (string, error) { return p.version, nil }
func (p *materialProcess) RotateLogs(context.Context) error        { return nil }
func (p *materialProcess) Stop(context.Context) error              { return nil }

type revokeProbe struct{ run func() }

func (p revokeProbe) Verify(context.Context, edge.Plan, string) (edge.RouteVerification, error) {
	p.run()
	return edge.RouteVerification{}, nil
}
func TestManagedLeafCurrentStatusAcrossPublicationAndRestore(t *testing.T) {
	for _, point := range []string{"after-stage", "during-probe"} {
		t.Run(point, func(t *testing.T) {
			m := newMaterialFixture(t)
			f := m.f
			s := f.site(t, "material")
			s.Draft.EntryCertificate = &id.MaterialRef{ID: m.spec.ID, Revision: 1, Status: "unavailable"}
			s = f.save(t, s)
			ex, c, plan := m.execution(t, s)
			if e := ex.Within(t.Context(), c.ID, plan, func() error { return nil }); e != nil {
				t.Fatal("good receipt", e)
			}
			draft := f.site(t, "unrelated-material")
			draft.Draft.Maintenance = id.MaintenancePolicy{Enabled: true, Status: 503, Message: "keep draft"}
			draft = f.save(t, draft)
			s.Draft.Maintenance = id.MaintenancePolicy{Enabled: true, Status: 503, Message: "second"}
			s = f.save(t, s)
			ex, c, plan = m.execution(t, s)
			disk := &materialDisk{}
			process := &materialProcess{version: "previous"}
			if point == "after-stage" {
				m.revoke(t)
				called := false
				if e := ex.ActivateWithin(t.Context(), c.ID, plan, func() error { called = true; return nil }); e == nil || called {
					t.Fatal("revoked staged material activated", e)
				}
			} else {
				supervisor := edge.NewSupervisor(process, disk, disk, nginx.Compiler{}, ex, revokeProbe{run: func() { m.revoke(t) }})
				result, e := supervisor.Apply(t.Context(), c.ID)
				if e == nil || result.State != "restore_failed" || result.RestoredVersion != "" || process.activations != 1 {
					t.Fatalf("probe revocation receipted/restored: %+v %v activations=%d", result, e, process.activations)
				}
			}
			if _, e := ex.Prepare(t.Context(), c.ID); e == nil {
				t.Fatal("revoked prepare accepted")
			}
			if _, e := f.pub.Prepare(t.Context(), f.admin, []string{s.ID}, selected(s)); e == nil {
				t.Fatal("revoked material preparation accepted")
			}
			if e := ex.Within(t.Context(), c.ID, plan, func() error { t.Fatal("revoked final receipt effect"); return nil }); e == nil {
				t.Fatal("revoked final receipt accepted")
			}
			for _, restore := range []func(context.Context, edge.Plan, func(context.Context) error) error{ex.RestoreActivateWithin, ex.WithRestore} {
				if e := restore(t.Context(), plan, func(context.Context) error { t.Fatal("revoked restore effect"); return nil }); e == nil {
					t.Fatal("revoked restore accepted")
				}
			}
			derivedDisk := &materialDisk{}
			before := process.activations
			observed, e := edge.NewSupervisor(process, derivedDisk, derivedDisk, nginx.Compiler{}, ex).ApplyDerived(t.Context(), "certificate")
			if e == nil || observed.State != "restore_failed" || process.activations != before {
				t.Fatal("derived revived revoked material", observed, e)
			}
			var state string
			if e = f.p.QueryRow(t.Context(), "SELECT state FROM deployment_releases WHERE id=$1", c.ID).Scan(&state); e != nil || state == "succeeded" {
				t.Fatal("revoked candidate receipt", state, e)
			}
			m.replace(t)
			restored, e := ex.CurrentVerified(t.Context())
			if e != nil {
				t.Fatal("valid replacement unavailable", e)
			}
			if len(restored.Snapshot.Sites) != 1 || restored.Snapshot.Sites[0].Config.Maintenance.Enabled {
				t.Fatal("replacement published unrelated/current draft")
			}
			if e = ex.WithRestore(t.Context(), restored, func(context.Context) error { return nil }); e != nil {
				t.Fatal("valid replacement restore denied", e)
			}
		})
	}
}

func TestImportedLocalLeafAndLegacyProvenanceFailClosed(t *testing.T) {
	m := newMaterialFixture(t)
	f := m.f
	var original cert.StoredVersion
	if e := f.tx.Within(t.Context(), func(sc transaction.Scope) error {
		var e error
		original, e = certpg.New().Current(sc, m.spec.ID, 1)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	specID, _ := f.ids.NewID()
	policy := m.policy
	policy.Method = "import"
	policy.ProviderID = ""
	policy.Challenge = ""
	body, _ := json.Marshal(policy)
	spec := cert.Record{Resource: cert.Resource{ID: specID, Kind: "spec", Revision: 1, Enabled: true, Body: body}}
	imported := original
	imported.ID, _ = f.ids.NewID()
	imported.SpecID = specID
	imported.Automatic = false
	imported.EnrollmentProvider = ""
	if e := f.tx.Within(t.Context(), func(sc transaction.Scope) error {
		r := certpg.New()
		if e := r.Save(sc, spec, 0); e != nil {
			return e
		}
		attempt, e := r.Claim(sc, specID, 1, imported.ID, time.Now().Add(time.Minute))
		if e != nil {
			return e
		}
		return r.Commit(sc, cert.Work{Spec: spec, Token: imported.ID, Attempt: attempt}, imported)
	}); e != nil {
		t.Fatal(e)
	}
	check := func(id string) error {
		return f.tx.Within(t.Context(), func(sc transaction.Scope) error {
			return m.service.ValidateMaterialsWithin(sc, []cert.MaterialRef{{ID: id, Kind: "certificate", Revision: 1}})
		})
	}
	if e := check(specID); e != nil {
		t.Fatal("good local imported leaf denied", e)
	}
	enroller := cert.New(f.tx, certpg.New(), certificateaccess.Graph{Ingress: f.in}, certcrypto.Crypto{}, fixturePlainSecrets{}, unusedMaterialIssuer{}, nil)
	if version, e := enroller.Ensure(t.Context(), specID); e != nil || version.ID != imported.ID {
		t.Fatal("existing imported certificate lost Ensure compatibility", version.ID, e)
	}

	// Legacy automatic metadata cannot infer public provenance from mutable account state.
	legacy := original
	legacy.ID, _ = f.ids.NewID()
	legacy.EnrollmentProvider = ""
	if e := f.tx.Within(t.Context(), func(sc transaction.Scope) error {
		r := certpg.New()
		attempt, e := r.Claim(sc, m.spec.ID, 1, legacy.ID, time.Now().Add(time.Minute))
		if e != nil {
			return e
		}
		return r.Commit(sc, cert.Work{Spec: m.spec, Token: legacy.ID, Attempt: attempt}, legacy)
	}); e != nil {
		t.Fatal(e)
	}
	if e := check(m.spec.ID); e == nil {
		t.Fatal("legacy automatic provenance guessed")
	}
	m.revoke(t)
	if e := check(specID); e == nil {
		t.Fatal("reimport revived revoked local leaf")
	}
}

type unusedMaterialIssuer struct{}

func (unusedMaterialIssuer) Obtain(context.Context, cert.Work) (cert.Issuance, error) {
	return cert.Issuance{}, fmt.Errorf("import unexpectedly attempted issuance")
}
