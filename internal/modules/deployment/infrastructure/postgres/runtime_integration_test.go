//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	dep "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/jobs"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRuntimeRejectsOldPublicationAndOrdering(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := pg.NewRunner(p)
	releases := dep.New()
	target := app.Target{ID: "g", Revision: 1, Config: app.TargetConfig{Protocol: "http", Members: []app.TargetMember{{Address: "10.0.0.2", Port: 80, Weight: 2}}, AllowedNetworks: []string{"10.0.0.0/8"}, Health: app.HealthPolicy{Enabled: true}}}
	publish := func(id string, target app.Target) {
		t.Helper()
		e := tx.Within(ctx, func(sc transaction.Scope) error {
			c := release.Candidate{ID: id, InputDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Snapshot: app.Snapshot{Version: id, Targets: []app.Target{target}}}
			if e := releases.Save(sc, c); e != nil {
				return e
			}
			if _, _, e := releases.Queue(sc, id); e != nil {
				return e
			}
			if e := releases.RecordOutcome(sc, id, "succeeded", "v", ""); e != nil {
				return e
			}
			return releases.RecordVerified(sc, id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "v")
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	publish("00000000-0000-4000-8000-000000000001", target)
	r := dep.NewRuntime(p, jobs.New(p), nil)
	w, e := r.Load(ctx, "g", 1)
	if e != nil {
		t.Fatal(e)
	}
	u := health.Update{Work: w, Sequence: w.Sequence + 1, Resolved: map[string][]netip.Addr{"10.0.0.2": {netip.MustParseAddr("10.0.0.2")}}, Results: []health.Sample{{Endpoint: "10.0.0.2:80", Identity: "10.0.0.2/10.0.0.2", Healthy: false}}}
	if _, e = r.Commit(ctx, u); e != nil {
		t.Fatal(e)
	}
	out, e := r.Commit(ctx, u)
	if e != nil || !out.Ignored {
		t.Fatal("duplicate consumed", out, e)
	}

	// DNS failures are owner-fenced results, not unsequenced worker diagnostics.
	if e = r.DNSFailure(ctx, w); e != nil {
		t.Fatal(e)
	}
	var alarms int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type='TargetDNSChanged' AND payload->>'state'='firing'`).Scan(&alarms); e != nil || alarms != 0 {
		t.Fatal("stale failure reactivated DNS", alarms, e)
	}
	fresh, e := r.Load(ctx, "g", 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.DNSFailure(ctx, fresh); e != nil {
		t.Fatal(e)
	}
	if e = r.DNSFailure(ctx, fresh); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type='TargetDNSChanged' AND payload->>'state'='firing'`).Scan(&alarms); e != nil || alarms != 1 {
		t.Fatal("DNS outcome not durable or duplicate", alarms, e)
	}
	fresh, e = r.Load(ctx, "g", 1)
	if e != nil {
		t.Fatal(e)
	}
	recovery := u
	recovery.Work = fresh
	recovery.Sequence = fresh.Sequence + 1
	if _, e = r.Commit(ctx, recovery); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type='TargetDNSChanged' AND payload->>'state'='resolved'`).Scan(&alarms); e != nil || alarms != 2 {
		t.Fatal("DNS recovery missing", alarms, e)
	}
	old := w
	target.Revision = 2
	target.Config.Members[0].Address = "10.0.0.3"
	publish("00000000-0000-4000-8000-000000000002", target)
	u.Work = old
	u.Sequence++
	out, e = r.Commit(ctx, u)
	if e != nil || !out.Ignored {
		t.Fatal("old publication applied", out, e)
	}
}

func TestRuntimeMissingBindingsRecoverAndEnqueueFailureRetainsDirty(t *testing.T) {
	p := testkit.Postgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := app.Target{ID: "g", Revision: 1, Config: app.TargetConfig{Protocol: "http", Members: []app.TargetMember{{Address: "backend.internal", Port: 80, Weight: 1}}, AllowedNetworks: []string{"10.0.0.0/8"}, Health: app.HealthPolicy{Enabled: true}}}
	snapshot := app.Snapshot{Version: "00000000-0000-4000-8000-000000000003", Targets: []app.Target{target}}
	tx := pg.NewRunner(p)
	store := dep.New()
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		if e := store.Save(sc, release.Candidate{ID: snapshot.Version, InputDigest: strings.Repeat("a", 64), Snapshot: snapshot}); e != nil {
			return e
		}
		if _, _, e := store.Queue(sc, snapshot.Version); e != nil {
			return e
		}
		if e := store.RecordOutcome(sc, snapshot.Version, "succeeded", "v", ""); e != nil {
			return e
		}
		return store.RecordVerified(sc, snapshot.Version, strings.Repeat("a", 64), "v")
	}); e != nil {
		t.Fatal(e)
	}
	r := dep.NewRuntime(p, jobs.New(p), nil)
	// Binding reads fail closed, but the scheduler's logical read stays usable.
	if e := tx.Within(ctx, func(sc transaction.Scope) error { _, e := r.BindWithin(sc, snapshot, edge.RuntimeState{}); return e }); e == nil {
		t.Fatal("missing DNS binding accepted")
	}
	if logical, e := r.Snapshot(ctx); e != nil || logical.Version != snapshot.Version {
		t.Fatal("logical read depended on missing runtime", e)
	}
	w, e := r.Load(ctx, "g", 1)
	if e != nil {
		t.Fatal(e)
	}
	out, e := r.Commit(ctx, health.Update{Work: w, Sequence: 1, Resolved: map[string][]netip.Addr{"backend.internal": {netip.MustParseAddr("10.0.0.2")}}, Results: []health.Sample{{Endpoint: "10.0.0.2:80", Identity: "backend.internal/backend.internal", Healthy: true}}})
	if e != nil || !out.Changed {
		t.Fatal(out, e)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		state, e := r.BindWithin(sc, snapshot, edge.RuntimeState{})
		if e == nil && len(state.Resolved) != 1 {
			t.Fatal(state)
		}
		return e
	}); e != nil {
		t.Fatal("runtime did not recover", e)
	}
	if _, e = p.Exec(ctx, `CREATE FUNCTION fail_generation_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected enqueue failure'; END; $$; CREATE TRIGGER fail_generation_enqueue BEFORE INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION fail_generation_enqueue()`); e != nil {
		t.Fatal(e)
	}
	if e = r.Flush(ctx); e == nil {
		t.Fatal("injected enqueue failure ignored")
	}
	var dirty bool
	var count int
	if e = p.QueryRow(ctx, "SELECT dirty FROM deployment_generation").Scan(&dirty); e != nil || !dirty {
		t.Fatal("dirty marker lost", dirty, e)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&count); e != nil || count != 0 {
		t.Fatal("partial job", count, e)
	}
	if _, e = p.Exec(ctx, "DROP TRIGGER fail_generation_enqueue ON jobs"); e != nil {
		t.Fatal(e)
	}
	if e = r.Flush(ctx); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, "SELECT dirty FROM deployment_generation").Scan(&dirty); e != nil || dirty {
		t.Fatal("dirty marker not acknowledged", dirty, e)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE kind='deployment.generation'").Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	// Counters and successful DNS identity-equivalent refreshes cannot reload.
	w, e = r.Load(ctx, "g", 1)
	if e != nil {
		t.Fatal(e)
	}
	out, e = r.Commit(ctx, health.Update{Work: w, Sequence: w.Sequence + 1, Resolved: map[string][]netip.Addr{"backend.internal": {netip.MustParseAddr("10.0.0.2")}}, Results: []health.Sample{{Endpoint: "10.0.0.2:80", Identity: "backend.internal/backend.internal", Healthy: false}}})
	if e != nil || out.Changed || out.Generation != "1" {
		t.Fatal("unchanged result must retain current generation", out, e)
	}
	if e = r.Flush(ctx); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&count); e != nil || count != 1 {
		t.Fatal("counter triggered reload", count, e)
	}
}

func TestRuntimeRejectsUnsupportedHealthCapacityBeforeActivation(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	r := dep.NewRuntime(p, jobs.New(p), nil)
	target := app.Target{ID: "large", Revision: 1, Config: app.TargetConfig{Protocol: "http", AllowedNetworks: []string{"10.0.0.0/8"}, Health: app.HealthPolicy{Enabled: true, IntervalSeconds: 60, TimeoutSeconds: 60}}}
	for i := 1; i <= 9; i++ {
		target.Config.Members = append(target.Config.Members, app.TargetMember{Address: fmt.Sprintf("10.0.0.%d", i), Port: 80, Weight: 1})
	}
	snapshot := app.Snapshot{Version: "unsupported", Targets: []app.Target{target}}
	if e := r.Prepare(ctx, snapshot); !errors.Is(e, domain.ErrHealthCapacity) {
		t.Fatal("infeasible group prepared", e)
	}
	var count int
	if e := p.QueryRow(ctx, "SELECT count(*) FROM deployment_target_runtime").Scan(&count); e != nil || count != 0 {
		t.Fatal("unsupported group persisted", count, e)
	}
	if e := pg.NewRunner(p).Within(ctx, func(sc transaction.Scope) error { _, e := r.BindWithin(sc, snapshot, edge.RuntimeState{}); return e }); !errors.Is(e, domain.ErrHealthCapacity) {
		t.Fatal("infeasible group activated via direct binding", e)
	}
}
