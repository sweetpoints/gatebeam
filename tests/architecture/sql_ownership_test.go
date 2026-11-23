//go:build integration

package main

import (
	"gatebeam/internal/platform/testkit"
	deploymentfixture "gatebeam/tests/fixtures/deployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
)

// This executes the maintained deployment grants, not a fixture GRANT ALL.
func TestCombinedRuntimeRolesRejectForeignCapabilities(t *testing.T) {
	p := testkit.Postgres(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	deploymentfixture.ApplyRoles(t, p, suffix)
	for _, name := range []string{"api", "worker", "edge", "ca"} {
		role := pgx.Identifier{"gatebeam_runtime_" + name + suffix}.Sanitize()
		if _, e := p.Exec(t.Context(), "GRANT USAGE ON SCHEMA "+pgx.Identifier{p.Config().ConnConfig.RuntimeParams["search_path"]}.Sanitize()+" TO "+role); e != nil {
			t.Fatal(e)
		}
		denied := []string{"CREATE TABLE forbidden(id int)", "DELETE FROM pki_restore_quarantine", "UPDATE identity_restore_bootstrap SET available=true"}
		if name != "ca" {
			denied = append(denied, "INSERT INTO pki_serial_reservations(issuer_id,serial) VALUES ('forbidden','01')", "SELECT der FROM pki_certificates")
		}
		if name == "ca" {
			denied = append(denied, "SELECT * FROM identity_accounts", "SELECT secret FROM certificates_revisions", "UPDATE ingress_sites SET published_revision=1")
		}
		if name == "edge" {
			denied = append(denied, "SELECT secret FROM certificates_revisions", "INSERT INTO certificates_issuance_leases(spec_id) VALUES (gen_random_uuid())", "UPDATE identity_accounts SET state='disabled'")
		}
		if name == "worker" {
			denied = append(denied, "UPDATE identity_accounts SET state='disabled'", "UPDATE ingress_sites SET published_revision=1")
		}
		for _, query := range denied {
			tx, e := p.Begin(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(t.Context(), "SET LOCAL ROLE "+role); e != nil {
				t.Fatal(e)
			}
			_, e = tx.Exec(t.Context(), query)
			tx.Rollback(t.Context())
			pe, ok := e.(*pgconn.PgError)
			if !ok || pe.Code != "42501" {
				t.Errorf("%s negative capability was not permission denied: %s: %v", name, query, e)
			}
		}
	}
}
