//go:build integration

package deployment

import (
	"context"
	"gatebeam/internal/platform/testkit"
	"github.com/jackc/pgx/v5"
	"sync"
	"testing"
	"time"
)

func TestRoleCleanupTerminatesOnlyOwnedIdleTransaction(t *testing.T) {
	pool := testkit.Postgres(t)
	survivor := RuntimeRoles(t, pool)["api"]
	survivorConfig := pool.Config().ConnConfig.Copy()
	survivorConfig.User, survivorConfig.Password = survivor.Name, survivor.Password
	protected, err := pgx.ConnectConfig(t.Context(), survivorConfig)
	if err != nil {
		t.Fatal("unrelated fixture connection unavailable")
	}
	var abandoned *pgx.Conn
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
		defer cancel()
		if abandoned != nil {
			_ = abandoned.Close(ctx)
		}
		_ = protected.Close(ctx)
	})
	var ownedPID int32
	var ownedRole string
	if !t.Run("owned_role_lifecycle", func(t *testing.T) {
		login := RuntimeRoles(t, pool)["api"]
		ownedRole = login.Name
		config := pool.Config().ConnConfig.Copy()
		config.User, config.Password = login.Name, login.Password
		var err error
		abandoned, err = pgx.ConnectConfig(t.Context(), config)
		if err != nil {
			t.Fatal("owned fixture connection unavailable")
		}
		ownedPID = int32(abandoned.PgConn().PID())
		if _, err = abandoned.Exec(t.Context(), "BEGIN"); err != nil {
			t.Fatal("owned transaction unavailable")
		}
		if _, err = abandoned.Exec(t.Context(), "SELECT 1 FROM ingress_sites LIMIT 1"); err != nil {
			t.Fatal("owned relation lock unavailable")
		}
		// Deliberately retain this idle transaction across the role cleanup, just
		// as a lost fault-fixture client can leave a backend holding table locks.
	}) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), roleFixtureBudget())
	defer cancel()
	// Schema teardown needs this lock mode. Prove that the retained client
	// cannot leave DDL blocked, rather than checking only backend metadata.
	ddl, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("cleanup lock verification unavailable")
	}
	defer func() {
		rollback, done := context.WithTimeout(context.Background(), roleFixtureBudget())
		defer done()
		_ = ddl.Rollback(rollback)
	}()
	if _, err = ddl.Exec(ctx, "LOCK TABLE ingress_sites IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal("role cleanup left schema teardown blocked by its retained transaction")
	}
	if err = ddl.Rollback(ctx); err != nil {
		t.Fatal("cleanup lock verification did not release its transaction")
	}
	for {
		var alive bool
		if err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", ownedPID).Scan(&alive); err != nil {
			t.Fatal("owned backend status unavailable")
		}
		if !alive {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("role cleanup retained its idle transaction backend")
		case <-time.After(10 * time.Millisecond):
		}
	}
	var exists bool
	if err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", ownedRole).Scan(&exists); err != nil || exists {
		t.Fatal("owned fixture role was not removed")
	}
	var value int
	if err = protected.QueryRow(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatal("cleanup terminated an unrelated fixture role session")
	}
}

func TestRoleCleanupQuiescesAllOwnedConsumersBeforeObjectTeardown(t *testing.T) {
	pool := testkit.Postgres(t)
	protectedLogin := RuntimeRoles(t, pool)["api"]
	config := pool.Config().ConnConfig.Copy()
	config.User, config.Password = protectedLogin.Name, protectedLogin.Password
	protected, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		t.Fatal("protected fixture connection unavailable")
	}
	var consumers []*pgx.Conn
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
		defer cancel()
		for _, conn := range consumers {
			_ = conn.Close(ctx)
		}
		_ = protected.Close(ctx)
	})
	var names []string
	calls, stops := 0, 0
	if !t.Run("two_owned_role_sets", func(t *testing.T) {
		var stopped sync.Once
		quiesce := func() {
			calls++
			stopped.Do(func() {
				stops++
				before, cancel := context.WithTimeout(context.Background(), roleFixtureBudget())
				for _, name := range names {
					var canLogin bool
					if err := pool.QueryRow(before, "SELECT rolcanlogin FROM pg_roles WHERE rolname=$1", name).Scan(&canLogin); err != nil || !canLogin {
						t.Error("owned authority was revoked before consumer quiescence began")
					}
				}
				cancel()
				// Keep the abandoned clients open. The actual cleanup helper must
				// fence new logins and release BOTH backends' real relation locks.
				if err := QuiesceRuntimeRoles(pool, names); err != nil {
					t.Error("owned runtime backends did not quiesce", err)
					return
				}
				after, done := context.WithTimeout(context.Background(), roleFixtureBudget())
				defer done()
				for _, name := range names {
					var canLogin bool
					if err := pool.QueryRow(after, "SELECT rolcanlogin FROM pg_roles WHERE rolname=$1", name).Scan(&canLogin); err != nil || canLogin {
						t.Error("quiescence failed to fence a still-existing owned login")
					}
				}
				ddl, err := pool.Begin(after)
				if err != nil {
					t.Error("quiescence lock verification unavailable")
					return
				}
				if _, err := ddl.Exec(after, "LOCK TABLE ingress_sites IN ACCESS EXCLUSIVE MODE"); err != nil {
					t.Error("owned consumers retained relation locks before object teardown")
				}
				_ = ddl.Rollback(after)
			})
		}
		first := RuntimeRoles(t, pool, quiesce)["api"]
		second := RuntimeRoles(t, pool, quiesce)["api"]
		// Reject the entire mixed request before changing the first valid role.
		// The real connections opened below must therefore still authenticate.
		if err := QuiesceRuntimeRoles(pool, []string{first.Name, "gatebeam_runtime_api"}); err == nil {
			t.Fatal("cleanup accepted an unowned production role name")
		}
		for _, login := range []Login{first, second} {
			names = append(names, login.Name)
			cfg := pool.Config().ConnConfig.Copy()
			cfg.User, cfg.Password = login.Name, login.Password
			conn, err := pgx.ConnectConfig(t.Context(), cfg)
			if err != nil {
				t.Fatal("owned consumer connection unavailable")
			}
			consumers = append(consumers, conn)
			if _, err := conn.Exec(t.Context(), "BEGIN"); err != nil {
				t.Fatal("owned transaction unavailable")
			}
			if _, err := conn.Exec(t.Context(), "SELECT 1 FROM ingress_sites LIMIT 1"); err != nil {
				t.Fatal("owned consumer did not acquire its real relation lock")
			}
		}
	}) {
		return
	}
	if calls != 2 || stops != 1 {
		t.Fatal("owned role sets did not share one consumer shutdown")
	}
	ctx, cancel := context.WithTimeout(t.Context(), roleFixtureBudget())
	defer cancel()
	for _, name := range names {
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", name).Scan(&exists); err != nil || exists {
			t.Fatal("owned role teardown did not complete")
		}
	}
	var value int
	if err := protected.QueryRow(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatal("consumer shutdown affected an unrelated fixture session")
	}
}
