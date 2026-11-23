//go:build integration

package roles_test

import (
	"context"
	"encoding/json"
	cert "gatebeam/internal/modules/certificates/application"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	fixture "gatebeam/tests/fixtures/deployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

func TestManualCertificateImportUsesManagementPrivilegesOnly(t *testing.T) {
	p := testkit.Postgres(t)
	roles := fixture.RuntimeRoles(t, p)
	cfg := p.Config().Copy()
	cfg.ConnConfig.User = roles["api"].Name
	cfg.ConnConfig.Password = roles["api"].Password
	api, e := pgxpool.NewWithConfig(t.Context(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	id := uuid.NewString()
	body, _ := json.Marshal(cert.Spec{Names: []string{"owned.test"}, Purpose: "serverAuth", Method: "import"})
	if _, e = p.Exec(t.Context(), `INSERT INTO certificates_resources(kind,id,revision,enabled) VALUES('spec',$1,1,true)`, id); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO certificates_revisions(kind,id,revision,body,secret) VALUES('spec',$1,1,$2,'')`, id, body); e != nil {
		t.Fatal(e)
	}
	token := uuid.NewString()
	store := certpg.New()
	version := cert.Version{ID: uuid.NewString(), SpecID: id, SpecRevision: 1, Automatic: false}
	e = postgres.NewRunner(api).Within(t.Context(), func(sc transaction.Scope) error {
		if _, e := store.Claim(sc, id, 1, token, time.Now().Add(time.Minute)); e != nil {
			return e
		}
		return store.Commit(sc, cert.Work{Spec: cert.Record{Resource: cert.Resource{ID: id, Kind: "spec", Revision: 1, Body: body}}, Token: token}, cert.StoredVersion{Version: version, CertificatePEM: []byte("owned certificate fixture"), EncryptedKey: []byte("sealed-owned-fixture")})
	})
	if e != nil {
		t.Fatal("manual import rolled back under actual API capability", e)
	}
	var count int
	if e = p.QueryRow(context.Background(), `SELECT count(*) FROM certificates_versions WHERE spec_id=$1`, id).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	if e = p.QueryRow(context.Background(), `SELECT count(*) FROM certificates_alert_outcomes WHERE resource_id=$1`, id).Scan(&count); e != nil || count != 0 {
		t.Fatal("manual import produced renewal alert", count, e)
	}
}
