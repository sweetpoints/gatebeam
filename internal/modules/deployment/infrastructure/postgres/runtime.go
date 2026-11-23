package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/dns"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/jobs"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/netip"
	"time"
)

type targetRuntime struct {
	Resolved map[string][]netip.Addr        `json:"resolved"`
	Members  map[string]domain.MemberHealth `json:"members"`
}
type Runtime struct {
	tx       transaction.Runner
	jobs     *jobs.Store
	resolver dns.Targets
}

func NewRuntime(p *pgxpool.Pool, j *jobs.Store, protected []netip.Prefix) *Runtime {
	return &Runtime{pg.NewRunner(p), j, dns.Targets{Protected: protected}}
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func binding(t app.Target) string { return digest(t) }
func readTarget(sc transaction.Scope, t app.Target) (v targetRuntime, sequence int64, token string, err error) {
	v = targetRuntime{Resolved: map[string][]netip.Addr{}, Members: map[string]domain.MemberHealth{}}
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		r, e := q.TargetRuntime(ctx, binding(t))
		if e != nil {
			return e
		}
		sequence = r.Sequence
		token = digest(r.Body)
		return json.Unmarshal(r.Body, &v)
	})
	if errors.Is(err, domain.ErrNotFound) {
		err = nil
		token = "missing"
	}
	return
}
func saveTarget(sc transaction.Scope, t app.Target, v targetRuntime, seq int64) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		return q.SaveTargetRuntime(ctx, dbgen.SaveTargetRuntimeParams{Binding: binding(t), Body: b, Sequence: seq, CheckedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}})
	})
}
func currentSnapshot(sc transaction.Scope) (app.Snapshot, error) {
	s := New()
	receipt, e := s.CurrentVerified(sc)
	if e != nil {
		return app.Snapshot{}, e
	}
	c, e := s.Read(sc, receipt.ReleaseID)
	if e == nil && c.State != domain.Succeeded {
		return app.Snapshot{}, domain.ErrInvalid
	}
	c.Snapshot.Version = receipt.ReleaseID
	return c.Snapshot, e
}
func (r *Runtime) Snapshot(ctx context.Context) (out app.Snapshot, err error) {
	err = r.tx.Within(ctx, func(sc transaction.Scope) error { var e error; out, e = currentSnapshot(sc); return e })
	return
}
func (r *Runtime) Load(ctx context.Context, id string, revision int64) (w health.Work, err error) {
	err = r.tx.Within(ctx, func(sc transaction.Scope) error {
		snapshot, e := currentSnapshot(sc)
		if e != nil {
			return e
		}
		for _, t := range snapshot.Targets {
			if t.ID == id && t.Revision == revision {
				w.ReleaseID = snapshot.Version
				w.Target = t
				_, w.Sequence, w.Token, e = readTarget(sc, t)
				return e
			}
		}
		return domain.ErrConflict
	})
	return
}
func (r *Runtime) Commit(ctx context.Context, u health.Update) (out health.Transition, err error) {
	err = r.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := use(sc, func(ctx context.Context, q *dbgen.Queries) error {
			v, e := q.RuntimeFence(ctx)
			out.Generation = fmt.Sprint(v.Generation)
			return e
		}); e != nil {
			return e
		}
		snapshot, e := currentSnapshot(sc)
		if e != nil {
			return e
		}
		out.Revision = u.Work.Target.Revision
		valid := snapshot.Version == u.Work.ReleaseID
		found := false
		for _, t := range snapshot.Targets {
			if binding(t) == binding(u.Work.Target) {
				found = true
			}
		}
		if !valid || !found {
			out.Ignored = true
			return nil
		}
		old, seq, token, e := readTarget(sc, u.Work.Target)
		if e != nil {
			return e
		}
		current := domain.ProbeBinding{ReleaseID: snapshot.Version, TargetRevision: u.Work.Target.Revision, MemberFingerprint: binding(u.Work.Target), ResolutionToken: token, Sequence: seq}
		started := domain.ProbeBinding{ReleaseID: u.Work.ReleaseID, TargetRevision: u.Work.Target.Revision, MemberFingerprint: binding(u.Work.Target), ResolutionToken: u.Work.Token, Sequence: u.Work.Sequence}
		if !current.Accepts(started, u.Sequence) {
			out.Ignored = true
			return nil
		}
		next := targetRuntime{Resolved: u.Resolved, Members: map[string]domain.MemberHealth{}}
		// DNS membership is part of the sample identity. A new resolution cannot
		// inherit a failure verdict for the same IP from a different hostname/member.
		for _, sample := range u.Results {
			key := sample.Identity + "|" + sample.Endpoint
			state := old.Members[key]
			p := health.Policy(u.Work.Target.Config.Health)
			state, _ = state.Observe(u.Sequence, sample.Healthy, domain.HealthThresholds{Failures: p.Failures, Successes: p.Successes})
			next.Members[key] = state
		}
		out.Changed = digest(effective(old)) != digest(effective(next))
		if e = saveTarget(sc, u.Work.Target, next, u.Sequence); e != nil {
			return e
		}

		if e = alertOutcome(sc, "TargetDNSChanged", u.Work.Target.ID, "dns", "resolved", 0); e != nil {
			return e
		}
		healthState := "resolved"
		for _, member := range next.Members {
			if member.Unhealthy {
				healthState = "firing"
			}
		}
		if e = alertOutcome(sc, "TargetHealthChanged", u.Work.Target.ID, "health", healthState, 0); e != nil {
			return e
		}
		if out.Changed {
			e = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
				g, e := q.RuntimeDirty(ctx)
				out.Generation = fmt.Sprint(g)
				return e
			})
		}
		return e
	})
	return
}
func effective(v targetRuntime) any {
	down := map[string]bool{}
	for key, state := range v.Members {
		if state.Unhealthy {
			down[key] = true
		}
	}
	return struct {
		Resolved map[string][]netip.Addr
		Down     map[string]bool
	}{v.Resolved, down}
}

// Prepare resolves immutable candidate bindings outside transactions. It never
// schedules activation or probes unpublished targets. Insert-only persistence
// cannot overwrite a newer worker resolution or health result.
func (r *Runtime) Prepare(ctx context.Context, snapshot app.Snapshot) error {
	for _, t := range snapshot.Targets {
		exists := false
		var prepared targetRuntime
		e := r.tx.Within(ctx, func(sc transaction.Scope) error {
			v, _, token, e := readTarget(sc, t)
			prepared = v
			exists = token != "missing"
			return e
		})
		if e != nil {
			return e
		}
		if exists {
			if _, e := health.Budget(t, prepared.Resolved); e != nil {
				return e
			}
			continue
		}
		answers, e := r.resolver.Resolve(ctx, t)
		if e != nil {
			return e
		}
		if _, e = health.Budget(t, answers); e != nil {
			return e
		}
		e = r.tx.Within(ctx, func(sc transaction.Scope) error {
			if e := use(sc, func(ctx context.Context, q *dbgen.Queries) error { _, e := q.RuntimeFence(ctx); return e }); e != nil {
				return e
			}
			_, _, token, e := readTarget(sc, t)
			if e != nil || token != "missing" {
				return e
			}
			return saveTarget(sc, t, targetRuntime{Resolved: answers, Members: map[string]domain.MemberHealth{}}, 0)
		})
		if e != nil {
			return e
		}
	}
	return nil
}

// BindWithin is network-free. Shared generation fencing is held through the
// final native effect; producer updates cannot race the artifact equality check.
func (r *Runtime) BindWithin(sc transaction.Scope, snapshot app.Snapshot, state edge.RuntimeState) (edge.RuntimeState, error) {
	if e := use(sc, func(ctx context.Context, q *dbgen.Queries) error { _, e := q.RuntimeReadFence(ctx); return e }); e != nil {
		return state, e
	}
	state.Resolved = map[string]edge.Resolution{}
	state.Health = map[string]edge.Health{}
	for _, t := range snapshot.Targets {
		v, _, _, e := readTarget(sc, t)
		if e != nil {
			return state, e
		}
		h := edge.Health{TargetRevision: t.Revision, Unhealthy: map[string]bool{}}
		for _, m := range t.Config.Members {
			ips := v.Resolved[m.Address]
			if len(ips) == 0 {
				if ip, e := netip.ParseAddr(m.Address); e == nil {
					ips = []netip.Addr{ip}
				} else {
					return state, domain.ErrUnavailable
				}
			}
			state.Resolved[t.ID+"/"+m.Address] = edge.Resolution{TargetRevision: t.Revision, Addresses: ips}
		}
		answers := map[string][]netip.Addr{}
		for _, m := range t.Config.Members {
			answers[m.Address] = state.Resolved[t.ID+"/"+m.Address].Addresses
		}
		if _, e := health.Budget(t, answers); e != nil {
			return state, e
		}
		for key, member := range v.Members {
			if member.Unhealthy {
				for i := len(key) - 1; i >= 0; i-- {
					if key[i] == '|' {
						h.Unhealthy[key[i+1:]] = true
						break
					}
				}
			}
		}
		if t.Config.Health.Enabled {
			state.Health[t.ID] = h
		}
	}
	state.DNSGeneration = digest(state.Resolved)
	state.HealthGeneration = digest(state.Health)
	state.Generation = digest([]string{state.Generation, state.DNSGeneration, state.HealthGeneration})
	return state, nil
}

// Flush merges all producer changes into one fixed edge job, at most once per
// second. The dirty marker survives crashes and is cleared atomically with job
// enqueue; an old queued job still binds CURRENT verified state at execution.
func (r *Runtime) Flush(ctx context.Context) error {
	return r.tx.Within(ctx, func(sc transaction.Scope) error {
		var v dbgen.RuntimeFenceRow
		if e := use(sc, func(ctx context.Context, q *dbgen.Queries) error { var e error; v, e = q.RuntimeFence(ctx); return e }); e != nil {
			return e
		}
		if !v.Dirty || (v.QueuedAt.InfinityModifier == pgtype.Finite && time.Since(v.QueuedAt.Time) < time.Second) {
			return nil
		}
		if _, e := NewEvents(r.jobs).EnqueueWithin(sc, "deployment.generation", fmt.Sprintf("health-dns/%d", v.Generation), json.RawMessage(`{"kind":"health"}`)); e != nil {
			return e
		}
		return use(sc, func(ctx context.Context, q *dbgen.Queries) error { return q.RuntimeQueued(ctx) })
	})
}

func (r *Runtime) Site(ctx context.Context, id string) (app.Site, error) {
	s, e := r.Snapshot(ctx)
	if e != nil {
		return app.Site{}, e
	}
	for _, site := range s.Sites {
		if site.ID == id {
			return site, nil
		}
	}
	return app.Site{}, domain.ErrNotFound
}

func (r *Runtime) DNSFailure(ctx context.Context, w health.Work) error {
	return r.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := use(sc, func(ctx context.Context, q *dbgen.Queries) error { _, e := q.RuntimeFence(ctx); return e }); e != nil {
			return e
		}
		snapshot, e := currentSnapshot(sc)
		if e != nil {
			return e
		}
		if snapshot.Version != w.ReleaseID {
			return nil
		}
		found := false
		for _, t := range snapshot.Targets {
			if binding(t) == binding(w.Target) {
				found = true
			}
		}
		if !found {
			return nil
		}
		current, seq, token, e := readTarget(sc, w.Target)
		if e != nil {
			return e
		}
		if seq != w.Sequence || token != w.Token {
			return nil
		}
		if e = saveTarget(sc, w.Target, current, seq+1); e != nil {
			return e
		}
		return alertOutcome(sc, "TargetDNSChanged", w.Target.ID, "dns", "firing", 0)
	})
}
