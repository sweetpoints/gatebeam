//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"gatebeam/internal/platform/testkit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
)

func TestObservabilityReaderCannotMutateProducerState(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	var schema string
	if e := p.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	role := pgx.Identifier{"o1_reader_" + strings.TrimPrefix(schema, "test_")}.Sanitize()
	if _, e := p.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if _, e := p.Exec(ctx, "DROP OWNED BY "+role); e != nil {
			t.Error(e)
		}
		if _, e := p.Exec(ctx, "DROP ROLE "+role); e != nil {
			t.Error(e)
		}
	}()
	for _, sql := range []string{"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + role, "GRANT SELECT ON observability_stats TO " + role} {
		if _, e := p.Exec(ctx, sql); e != nil {
			t.Fatal(e)
		}
	}
	conn, e := p.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Release()
	if _, e = conn.Exec(ctx, "SET ROLE "+role); e != nil {
		t.Fatal(e)
	}
	defer conn.Exec(ctx, "RESET ROLE")
	if _, e = conn.Exec(ctx, "SELECT * FROM observability_stats"); e != nil {
		t.Fatal(e)
	}
	for _, query := range []string{"SELECT * FROM observability_segments", "SELECT * FROM observability_batches", "DELETE FROM observability_stats", "SELECT * FROM pki_issuers"} {
		if _, e = conn.Exec(ctx, query); e == nil {
			t.Fatal("reader overprivileged", query)
		}
	}
}

func TestHistoryAPIRoleCannotMutateArchiveOrReadCA(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	var schema string
	if e := p.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	role := pgx.Identifier{"o2_api_" + strings.TrimPrefix(schema, "test_")}.Sanitize()
	if _, e := p.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); e != nil {
		t.Fatal(e)
	}
	defer func() { p.Exec(ctx, "DROP OWNED BY "+role); p.Exec(ctx, "DROP ROLE "+role) }()
	for _, q := range []string{"GRANT USAGE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + role, "GRANT SELECT ON observability_manifests,observability_archive_objects TO " + role, "GRANT SELECT,INSERT,UPDATE,DELETE ON observability_queries TO " + role} {
		if _, e := p.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	conn, e := p.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Release()
	if _, e = conn.Exec(ctx, "SET ROLE "+role); e != nil {
		t.Fatal(e)
	}
	defer conn.Exec(ctx, "RESET ROLE")
	for _, q := range []string{"SELECT * FROM observability_manifests", "SELECT * FROM observability_queries"} {
		if _, e = conn.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	for _, q := range []string{"DELETE FROM observability_manifests", "UPDATE observability_archive_objects SET bytes=1", "SELECT * FROM observability_segments", "SELECT * FROM pki_issuers", "SELECT secret FROM certificates_revisions"} {
		if _, e = conn.Exec(ctx, q); e == nil {
			t.Fatal("API role boundary escaped", q)
		} else {
			var denied *pgconn.PgError
			if !errors.As(e, &denied) || denied.Code != "42501" {
				t.Fatal("negative fixture did not exercise privilege denial", q, e)
			}
		}
	}
}
