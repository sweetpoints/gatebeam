//go:build integration

package application_test

import (
	"encoding/json"
	app "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	repo "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestExpiryOfPublishedRevisionSurvivesNewDraftAndRecoversOnce(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	guard := security{tx}
	crypto := certcrypto.Crypto{}
	m := app.NewManagement(guard, guard, r, crypto, secret{}, secret{}, audit.New())
	spec := app.Spec{Names: []string{"owned.test"}, Purpose: "serverAuth", Method: "import"}
	resource, e := m.SaveSpec(t.Context(), app.ActorRef{}, "", 0, spec)
	if e != nil {
		t.Fatal(e)
	}
	install := func(until time.Time) {
		t.Helper()
		v := app.Version{ID: uuid.NewString(), SpecID: resource.ID, SpecRevision: 1, NotBefore: time.Now().Add(-time.Hour), NotAfter: until}
		body, _ := json.Marshal(v)
		if _, e = p.Exec(t.Context(), `INSERT INTO certificates_versions(id,spec_id,spec_revision,body,certificate_pem,encrypted_key) VALUES($1,$2,1,$3,'','')`, v.ID, resource.ID, body); e != nil {
			t.Fatal(e)
		}
		if _, e = p.Exec(t.Context(), `INSERT INTO certificates_attempts(spec_id,spec_revision,current_version) VALUES($1,1,$2) ON CONFLICT(spec_id,spec_revision) DO UPDATE SET current_version=excluded.current_version`, resource.ID, v.ID); e != nil {
			t.Fatal(e)
		}
	}
	install(time.Now().Add(time.Hour))
	if _, e = m.SaveSpec(t.Context(), app.ActorRef{}, resource.ID, 1, spec); e != nil {
		t.Fatal(e)
	}
	worker := app.New(tx, r, guard, crypto, nil, nil, nil)
	if e = worker.ObserveExpiry(t.Context(), resource.ID, 1); e != nil {
		t.Fatal(e)
	}
	if e = worker.ObserveExpiry(t.Context(), resource.ID, 2); e != nil {
		t.Fatal(e)
	}
	var state string
	if e = p.QueryRow(t.Context(), `SELECT state FROM certificates_alert_outcomes WHERE kind='CertificateExpiryChanged' AND fingerprint='1'`).Scan(&state); e != nil || state != "firing" {
		t.Fatal("new draft masked active expiry", state, e)
	}
	install(time.Now().Add(30 * 24 * time.Hour))
	for range 2 {
		if e = worker.ObserveExpiry(t.Context(), resource.ID, 1); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e = p.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE event_type='CertificateExpiryChanged'`).Scan(&count); e != nil || count != 2 {
		t.Fatal("recovery not once", count, e)
	}
}
