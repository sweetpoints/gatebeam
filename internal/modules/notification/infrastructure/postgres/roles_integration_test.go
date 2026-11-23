//go:build integration

package postgres_test

import (
	"gatebeam/internal/platform/testkit"
	deploymentfixture "gatebeam/tests/fixtures/deployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
)

func TestNotificationRoleCannotRewriteCredentialsOrReadCA(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	roles := []string{"gatebeam_notification_management", "gatebeam_notification_worker", "gatebeam_deployment_alert_writer"}
	deploymentfixture.ApplyRoles(t, p, suffix)
	schema := p.Config().ConnConfig.RuntimeParams["search_path"]
	if _, e := p.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+pgx.Identifier{roles[1] + suffix}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	for _, query := range []string{`UPDATE notification_channels SET secret='replacement'::bytea`, `SELECT encrypted_key FROM certificates_versions`, `SELECT seed FROM identity_accounts`, `SELECT * FROM pki_issuers`} {
		tx, e := p.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{roles[1] + suffix}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, query); e == nil {
			t.Fatal("notification role gained foreign or secret-write authority")
		}
		tx.Rollback(ctx)
	}
}
