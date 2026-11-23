//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"
)

func TestAuditMetadataReaderDoesNotRequirePayloadPrivilege(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	role := "o5_audit_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{role}.Sanitize()
	schema := pgx.Identifier{p.Config().ConnConfig.RuntimeParams["search_path"]}.Sanitize()
	if _, e := p.Exec(ctx, "CREATE ROLE "+quoted+" NOLOGIN"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, e := p.Exec(c, "DROP OWNED BY "+quoted+";DROP ROLE "+quoted); e != nil {
			t.Error("audit fixture role cleanup failed")
		}
	})
	if _, e := p.Exec(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO "+quoted+";GRANT SELECT(id,actor_id,action,occurred_at) ON audit TO "+quoted); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO audit(id,actor_id,action,payload)VALUES('audit-owned','actor-owned','identity.token.revoked','{"private_key":"must-not-select","arbitrary":{"token":"must-not-return"}}')`); e != nil {
		t.Fatal(e)
	}
	e := platform.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		if e := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error { _, e := tx.Exec(ctx, "SET LOCAL ROLE "+quoted); return e }); e != nil {
			return e
		}
		rows, e := repo.New().ListAudit(sc, 25, 0)
		if e != nil {
			return e
		}
		if len(rows) != 1 || rows[0].Action != "identity.token.revoked" {
			t.Fatal("safe audit metadata missing")
		}
		raw, _ := json.Marshal(rows)
		if strings.Contains(string(raw), "must-not") || strings.Contains(string(raw), "payload") {
			t.Fatal("audit payload escaped metadata contract")
		}
		return nil
	})
	if e != nil {
		t.Fatal("safe metadata query needs secret payload privilege", e)
	}
}
