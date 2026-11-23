//go:build integration

package postgres_test

import (
	"context"
	"gatebeam/internal/composition"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var capabilityRoles = []string{
	"gatebeam_deployment_node_admin",
	"gatebeam_runtime_api", "gatebeam_runtime_worker", "gatebeam_runtime_edge", "gatebeam_runtime_ca",
	"gatebeam_pki_management", "gatebeam_pki_ca", "gatebeam_certificates_management", "gatebeam_certificates_worker", "gatebeam_certificates_edge",
	"gatebeam_observability_worker", "gatebeam_observability_reader", "gatebeam_observability_query_api",
	"gatebeam_notification_management", "gatebeam_notification_worker", "gatebeam_deployment_alert_writer",
	"gatebeam_backup_snapshot", "gatebeam_backup_worker", "gatebeam_backup_reader",
	"gatebeam_deployment_operations_reader", "gatebeam_deployment_operations_writer",
}

func roleFixture(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p := testkit.Postgres(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, name := range capabilityRoles {
			var exists bool
			if err := p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", name).Scan(&exists); err != nil {
				t.Error(err)
				continue
			}
			if exists {
				if _, err := p.Exec(ctx, "DROP OWNED BY "+pgx.Identifier{name}.Sanitize()); err != nil {
					t.Error(err)
				}
			}
		}
		for _, name := range capabilityRoles {
			if _, err := p.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Error(err)
			}
		}
	})
	return p
}

func TestRolesMigrateFreshAndExisting(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			p := roleFixture(t)
			var oldOID uint32
			if existing {
				if _, err := p.Exec(t.Context(), "CREATE ROLE gatebeam_runtime_api NOLOGIN"); err != nil {
					t.Fatal(err)
				}
				if err := p.QueryRow(t.Context(), "SELECT oid FROM pg_roles WHERE rolname='gatebeam_runtime_api'").Scan(&oldOID); err != nil {
					t.Fatal(err)
				}
			}
			secret := filepath.Join(t.TempDir(), "migration-database")
			if err := os.WriteFile(secret, []byte(p.Config().ConnString()), 0600); err != nil {
				t.Fatal(err)
			}
			if err := composition.Run(t.Context(), "migrate", bootstrap.Config{Mode: "migrate", DatabaseFile: secret, MigrateRoles: true}); err != nil {
				t.Fatal(err)
			}
			if err := postgres.MigrateRoles(t.Context(), p); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := p.QueryRow(t.Context(), "SELECT count(*) FROM gatebeam_role_version WHERE version_id=1 AND is_applied").Scan(&n); err != nil || n != 1 {
				t.Fatalf("role migration receipt count=%d err=%v", n, err)
			}
			var oid uint32
			var login, createRole, bypass bool
			if err := p.QueryRow(t.Context(), "SELECT oid,rolcanlogin,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname='gatebeam_runtime_api'").Scan(&oid, &login, &createRole, &bypass); err != nil || login || createRole || bypass || (existing && oid != oldOID) {
				t.Fatalf("role identity/capabilities changed: %v", err)
			}
			var issuerDER, dbCreate bool
			schema := p.Config().ConnConfig.RuntimeParams["search_path"]
			if err := p.QueryRow(t.Context(), "SELECT has_column_privilege('gatebeam_runtime_api','pki_certificates','der','SELECT'),has_schema_privilege('gatebeam_runtime_api',$1,'CREATE')", schema).Scan(&issuerDER, &dbCreate); err != nil || issuerDER || dbCreate {
				t.Fatalf("API gained forbidden capability: %v", err)
			}
			var allowed bool
			if err := p.QueryRow(t.Context(), "SELECT has_table_privilege('gatebeam_runtime_api','identity_sessions','SELECT,INSERT,UPDATE,DELETE')").Scan(&allowed); err != nil || !allowed {
				t.Fatalf("API cannot manage sessions: %v", err)
			}
		})
	}
}

func TestRolesRejectConflictingIdentity(t *testing.T) {
	for _, setup := range []string{
		"CREATE ROLE gatebeam_runtime_api LOGIN",
		"CREATE ROLE gatebeam_runtime_api NOLOGIN; CREATE TABLE role_owned(id int); ALTER TABLE role_owned OWNER TO gatebeam_runtime_api",
		"CREATE ROLE gatebeam_runtime_api NOLOGIN; GRANT pg_read_all_data TO gatebeam_runtime_api",
		"CREATE ROLE gatebeam_runtime_api NOLOGIN; CREATE ROLE gatebeam_pki_management NOLOGIN; GRANT gatebeam_pki_management TO gatebeam_runtime_api WITH ADMIN OPTION",
	} {
		t.Run(setup, func(t *testing.T) {
			p := roleFixture(t)
			if _, err := p.Exec(t.Context(), setup); err != nil {
				t.Fatal(err)
			}
			if err := postgres.MigrateRoles(t.Context(), p); err == nil {
				t.Fatal("accepted incompatible pre-existing runtime role")
			}
			var newlyCreated int
			if err := p.QueryRow(t.Context(), "SELECT count(*) FROM pg_roles WHERE rolname='gatebeam_runtime_worker'").Scan(&newlyCreated); err != nil || newlyCreated != 0 {
				t.Fatalf("failed migration partially created roles: %v", err)
			}
		})
	}
}

func TestConcurrentMigratorsSerialize(t *testing.T) {
	p := roleFixture(t)
	const schemaLock int64 = 0x474154454245414d
	const rolesLock int64 = 0x47415445524f4c45
	for _, check := range []struct {
		lock    int64
		blocked func(context.Context, *pgxpool.Pool) error
		other   func(context.Context, *pgxpool.Pool) error
		table   string
		version int
	}{{schemaLock, postgres.Migrate, postgres.MigrateRoles, "goose_db_version", 27}, {rolesLock, postgres.MigrateRoles, postgres.Migrate, "gatebeam_role_version", 6}} {
		// Up intentionally bypasses the session lock when there is no pending
		// migration. Make an owned fixture version pending without changing its
		// schema, then verify it cannot execute while another session holds the lock.
		if _, err := p.Exec(t.Context(), "DELETE FROM "+check.table+" WHERE version_id=$1", check.version); err != nil {
			t.Fatal(err)
		}
		conn, err := p.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = conn.Exec(t.Context(), "SELECT pg_advisory_lock($1)", check.lock); err != nil {
			t.Fatal(err)
		}
		if err = check.other(t.Context(), p); err != nil {
			t.Fatal("independent migration namespace blocked", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		err = check.blocked(ctx, p)
		expired := ctx.Err() == context.DeadlineExceeded
		cancel()
		_, unlockErr := conn.Exec(t.Context(), "SELECT pg_advisory_unlock($1)", check.lock)
		conn.Release()
		if unlockErr != nil || err == nil || !expired {
			t.Fatalf("migration ignored lock: migrate=%v unlock=%v", err, unlockErr)
		}
		if _, err := p.Exec(t.Context(), "INSERT INTO "+check.table+"(version_id,is_applied) VALUES($1,true)", check.version); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), "DELETE FROM gatebeam_role_version WHERE version_id=6"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() { errs <- postgres.MigrateRoles(t.Context(), p) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := p.QueryRow(t.Context(), "SELECT count(*) FROM gatebeam_role_version WHERE version_id=6 AND is_applied").Scan(&n); err != nil || n != 1 {
		t.Fatalf("concurrent migration history count=%d err=%v", n, err)
	}
}
