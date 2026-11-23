// Package deployment provisions only task-owned runtime capability fixtures.
package deployment

import (
	"context"
	"errors"
	"gatebeam/db/roles"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type Login struct{ Name, Password string }

// QuiesceRuntimeRoles is cleanup-only. Callers supply the exact fixture logins
// they created; bare shared/production roles are rejected before any SQL.
// Only supplied suffixed runtime names are fenced and drained. Client shutdown
// alone need not interrupt a backend's in-flight transaction.
func QuiesceRuntimeRoles(p *pgxpool.Pool, names []string) error {
	if len(names) == 0 {
		return nil
	}
	owned := regexp.MustCompile(`^gatebeam_runtime_(api|worker|edge|ca)[a-f0-9]{12}$`)
	for _, name := range names {
		if !owned.MatchString(name) {
			return errors.New("invalid owned runtime cleanup role")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
	defer cancel()
	for _, name := range names {
		if _, err := p.Exec(ctx, "ALTER ROLE "+pgx.Identifier{name}.Sanitize()+" NOLOGIN"); err != nil {
			return errors.Join(errors.New("owned runtime login fence unavailable"), ctx.Err())
		}
	}
	if _, err := p.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename::text=ANY($1::text[]) AND pid<>pg_backend_pid()", names); err != nil {
		return errors.Join(errors.New("owned runtime backend shutdown unavailable"), ctx.Err())
	}
	for {
		var active bool
		if err := p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename::text=ANY($1::text[]) AND pid<>pg_backend_pid())", names).Scan(&active); err != nil {
			return errors.Join(errors.New("owned runtime backend observation unavailable"), ctx.Err())
		}
		if !active {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func roleFixtureBudget() time.Duration {
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		return 60 * time.Second
	}
	return 5 * time.Second
}

// ApplyRoles executes the maintained goose role migrations with fixture-owned
// names. It never changes the cluster-wide production capability identities.
func ApplyRoles(t testing.TB, p *pgxpool.Pool, suffix string, beforeCleanup ...func()) map[string]string {
	t.Helper()
	if !regexp.MustCompile(`^[a-f0-9]{12,32}$`).MatchString(suffix) {
		t.Fatal("invalid fixture suffix")
	}
	entries, e := fs.ReadDir(roles.Files, ".")
	if e != nil {
		t.Fatal(e)
	}
	files := fstest.MapFS{}
	names := map[string]string{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		b, e := roles.Files.ReadFile(entry.Name())
		if e != nil {
			t.Fatal(e)
		}
		for _, match := range regexp.MustCompile(`gatebeam_[a-z_]+`).FindAllString(string(b), -1) {
			names[match] = match + suffix
		}
		files[entry.Name()] = &fstest.MapFile{Data: b}
	}
	pairs := []string{}
	for base, actual := range names {
		pairs = append(pairs, base, actual)
	}
	replace := strings.NewReplacer(pairs...)
	for _, file := range files {
		file.Data = []byte(replace.Replace(string(file.Data)))
	}
	t.Cleanup(func() {
		// Consumers can span several role sets in one owned database. Stop all
		// of them before revoking any set's grants, using a shared once hook.
		// Consumer shutdown must not spend the database cleanup's own budget.
		for _, stop := range beforeCleanup {
			if stop != nil {
				stop()
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
		defer cancel()
		for _, name := range names {
			var exists bool
			if e := p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", name).Scan(&exists); e != nil {
				t.Error(e)
				continue
			}
			if exists {
				// Lost fault-fixture clients can retain idle transactions even after
				// DROP ROLE. Revoke new logins and drain only this fixture's unique
				// role before removing grants; unrelated fixture sessions stay alive.
				if _, e := p.Exec(ctx, "ALTER ROLE "+pgx.Identifier{name}.Sanitize()+" NOLOGIN"); e != nil {
					t.Error(e)
					continue
				}
				if _, e := p.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()", name); e != nil {
					t.Error(e)
					continue
				}
				for {
					var active bool
					if e := p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid())", name).Scan(&active); e != nil {
						t.Error(e)
						break
					}
					if !active {
						break
					}
					select {
					case <-ctx.Done():
					case <-time.After(10 * time.Millisecond):
					}
				}
				if _, e := p.Exec(ctx, "DROP OWNED BY "+pgx.Identifier{name}.Sanitize()); e != nil {
					t.Error(e)
				}
			}
		}
		for _, name := range names {
			if _, e := p.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{name}.Sanitize()); e != nil {
				t.Error(e)
			}
		}
	})
	db := stdlib.OpenDBFromPool(p)
	defer db.Close()
	provider, e := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithDisableGlobalRegistry(true), goose.WithTableName("role_fixture_"+suffix))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
	defer cancel()
	if _, e = provider.Up(ctx); e != nil {
		t.Fatal(e)
	}
	return names
}

func RuntimeRoles(t testing.TB, p *pgxpool.Pool, beforeCleanup ...func()) map[string]Login {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	names := ApplyRoles(t, p, suffix, beforeCleanup...)
	ctx, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
	defer cancel()
	out := map[string]Login{}
	for _, name := range []string{"api", "worker", "edge", "ca"} {
		login := Login{Name: names["gatebeam_runtime_"+name], Password: uuid.NewString()}
		if _, e := p.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login.Name}.Sanitize()+" LOGIN PASSWORD '"+login.Password+"'"); e != nil {
			t.Fatal("fixture login provision failed")
		}
		if _, e := p.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{p.Config().ConnConfig.RuntimeParams["search_path"]}.Sanitize()+" TO "+pgx.Identifier{login.Name}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		out[name] = login
	}
	return out
}
