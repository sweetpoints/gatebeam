package runtime_test

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"sync"
	"testing"
	"time"
)

type routeProbe struct {
	mu    sync.Mutex
	paths []string
	fail  bool
}

func (p *routeProbe) CheckRoute(ctx context.Context, r edge.RouteProbe) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paths = append(p.paths, r.Path)
	if p.fail {
		return errors.New("backend down")
	}
	return ctx.Err()
}

type routeEvidence struct{ report edge.RouteVerification }

func (e *routeEvidence) SaveRouteVerification(_ context.Context, r edge.RouteVerification) error {
	e.report = r
	return nil
}
func routePlan() edge.Plan {
	return edge.Plan{Snapshot: app.Snapshot{Version: "v", Sites: []app.Site{{ID: "site", Revision: 2, Config: app.SiteConfig{Enabled: true, Domains: []string{"shop.test"}, DefaultTarget: app.TargetRef{ID: "backend"}, EntryCertificate: &app.MaterialRef{ID: "entry", Revision: 1}, Routes: []app.Route{{Match: "prefix", Path: "/api/", StripPrefix: true, Target: app.TargetRef{ID: "backend"}}}}}}, Targets: []app.Target{{ID: "backend", Revision: 3, Config: app.TargetConfig{Health: app.HealthPolicy{Enabled: true, Path: "/health"}}}}}, Runtime: edge.RuntimeState{Generation: "g", Materials: map[string]edge.Material{"entry": {Revision: 1, CertificatePEM: []byte("trusted-material")}}}}
}
func TestPostApplyWholePlanAndExplicitCapabilityOutcomes(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*edge.Plan)
		want   string
		calls  int
	}{{"all", func(*edge.Plan) {}, "verified", 2}, {"protected", func(p *edge.Plan) { p.Snapshot.Sites[0].Config.ClientVerification.Mode = "required" }, "policy_refused", 0}, {"no_readonly_authorization", func(p *edge.Plan) { p.Snapshot.Targets[0].Config.Health.Enabled = false }, "unavailable", 0}, {"maintenance", func(p *edge.Plan) { p.Snapshot.Sites[0].Config.Maintenance.Enabled = true }, "not_applicable", 0}} {
		t.Run(test.name, func(t *testing.T) {
			p := routePlan()
			test.modify(&p)
			probe := &routeProbe{}
			evidence := &routeEvidence{}
			report, err := (edge.RouteVerifier{Probe: probe, Evidence: evidence}).Verify(context.Background(), p, "artifact")
			if err != nil || len(report.Routes) != 2 || len(probe.paths) != test.calls {
				t.Fatalf("%+v %v calls=%v", report, err, probe.paths)
			}
			for _, r := range report.Routes {
				if r.Outcome != test.want || r.Host != "shop.test" || r.SNI != "shop.test" {
					t.Fatalf("unsafe/incomplete evidence %+v", r)
				}
			}
			if report.BusinessVerified != (test.want == "verified") {
				t.Fatal("private version used as business success")
			}
		})
	}
}

func TestPostApplyOnlyEnumeratesNativeLocations(t *testing.T) {
	p := routePlan()
	p.Snapshot.Sites[0].Config.DefaultTarget = app.TargetRef{ID: "unused"}
	p.Snapshot.Sites[0].Config.Routes = []app.Route{{Match: "prefix", Path: "/", Target: app.TargetRef{ID: "backend"}}}
	probe := &routeProbe{}
	report, err := (edge.RouteVerifier{Probe: probe, Evidence: &routeEvidence{}}).Verify(context.Background(), p, "artifact")
	if err != nil || !report.BusinessVerified || len(report.Routes) != 1 || len(probe.paths) != 1 || report.Routes[0].TargetID != "backend" {
		t.Fatalf("suppressed default location contaminated route evidence: %+v %v", report, err)
	}
}
func TestPostApplyFailureBudgetAndRouteInterception(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		probe := &routeProbe{fail: true}
		evidence := &routeEvidence{}
		report, err := (edge.RouteVerifier{Probe: probe, Evidence: evidence}).Verify(ctx, routePlan(), "artifact")
		cancel()
		if err == nil || report.BusinessVerified || len(evidence.report.Routes) != 2 {
			t.Fatal("failure was not durable", report, err)
		}
	}
	p := routePlan()
	p.Snapshot.Sites[0].Config.Routes = append(p.Snapshot.Sites[0].Config.Routes, app.Route{Match: "exact", Path: "/api/health", Target: app.TargetRef{ID: "other"}})
	probe := &routeProbe{}
	report, err := (edge.RouteVerifier{Probe: probe, Evidence: &routeEvidence{}}).Verify(context.Background(), p, "artifact")
	if err != nil || report.Routes[1].Reason != "read_only_probe_unmappable" || len(probe.paths) != 1 {
		t.Fatalf("intercepted route requested: %+v %v", report, err)
	}
}

type phaseAuthority struct {
	*authority
	activated, finalized bool
	rejectFinal          bool
}

func (a *phaseAuthority) ActivateWithin(_ context.Context, _ string, _ edge.Plan, fn func() error) error {
	a.activated = true
	return fn()
}
func (a *phaseAuthority) Within(_ context.Context, _ string, _ edge.Plan, fn func() error) error {
	if a.rejectFinal {
		return errors.New("authorization/lease/material changed")
	}
	if err := fn(); err != nil {
		return err
	}
	a.finalized = true
	return nil
}

type verificationFunc func(context.Context, edge.Plan, string) (edge.RouteVerification, error)

func (f verificationFunc) Verify(c context.Context, p edge.Plan, a string) (edge.RouteVerification, error) {
	return f(c, p, a)
}
func TestPostApplyPhasesRestoreBeforeFinalReceipt(t *testing.T) {
	for _, mode := range []string{"success", "probe_failure", "probe_timeout", "final_drift"} {
		t.Run(mode, func(t *testing.T) {
			_, disk, process, base := harness()
			authority := &phaseAuthority{authority: base}
			verifier := verificationFunc(func(_ context.Context, p edge.Plan, _ string) (edge.RouteVerification, error) {
				if p.Snapshot.Version == "old" {
					return edge.RouteVerification{BusinessVerified: true}, nil
				}
				if !authority.activated || authority.finalized || disk.j.State != domain.Verifying || !disk.j.ReceiptPending {
					t.Fatal("heads/receipt finalized before probe", disk.j)
				}
				if mode == "final_drift" {
					authority.rejectFinal = true
				}
				if mode == "probe_timeout" {
					ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
					defer cancel()
					<-ctx.Done()
					return edge.RouteVerification{}, ctx.Err()
				}
				if mode == "probe_failure" {
					return edge.RouteVerification{}, edge.ErrRouteVerification
				}
				return edge.RouteVerification{BusinessVerified: true}, nil
			})
			supervisor := edge.NewSupervisor(process, disk, disk, compiler{}, authority, verifier)
			result, err := supervisor.Apply(context.Background(), "new")
			if mode == "success" {
				if err != nil || !authority.finalized || result.State != "succeeded" {
					t.Fatal(result, err)
				}
			} else {
				if err == nil || authority.finalized || process.version != "old/g1" || result.State != "restored" {
					t.Fatal("did not safely restore", result, err)
				}
			}
		})
	}
}

func TestPostApplyRefusesAmbiguousReadOnlyMapping(t *testing.T) {
	for _, path := range []string{"/api/%2e%2e/mutate", "/api/../mutate", "//health"} {
		p := routePlan()
		p.Snapshot.Targets[0].Config.Health.Path = path
		probe := &routeProbe{}
		report, err := (edge.RouteVerifier{Probe: probe, Evidence: &routeEvidence{}}).Verify(context.Background(), p, "artifact")
		if err != nil || report.BusinessVerified || len(probe.paths) != 0 {
			t.Fatal("ambiguous GET executed", path, report, err)
		}
	}
	p := routePlan()
	p.Snapshot.Targets[0].Config.Health.HTTPHost = "other.test"
	probe := &routeProbe{}
	report, err := (edge.RouteVerifier{Probe: probe, Evidence: &routeEvidence{}}).Verify(context.Background(), p, "artifact")
	if err != nil || report.BusinessVerified || len(probe.paths) != 0 {
		t.Fatal("GET sent to unauthorized health Host", report, err)
	}
}

func TestPostApplyCapabilityRefusalCannotHideExecutedFailure(t *testing.T) {
	p := routePlan()
	protected := p.Snapshot.Sites[0]
	protected.ID = "protected"
	protected.Config.Cloudflare.Mode = "proxied"
	p.Snapshot.Sites = append(p.Snapshot.Sites, protected)
	report, err := (edge.RouteVerifier{Probe: &routeProbe{fail: true}, Evidence: &routeEvidence{}}).Verify(context.Background(), p, "artifact")
	if err == nil || report.BusinessVerified || len(report.Routes) != 4 || report.Routes[0].Outcome != "degraded" || report.Routes[2].Outcome != "policy_refused" {
		t.Fatal("actual failure hidden by capability refusal", report, err)
	}
}

type deadlineProbe struct{}

func (deadlineProbe) CheckRoute(ctx context.Context, _ edge.RouteProbe) error {
	<-ctx.Done()
	return ctx.Err()
}
func TestPostApplyInFlightTimeoutRemainsDurableFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	evidence := &routeEvidence{}
	report, err := (edge.RouteVerifier{Probe: deadlineProbe{}, Evidence: evidence}).Verify(ctx, routePlan(), "artifact")
	if err == nil || report.BusinessVerified || len(evidence.report.Routes) != 2 {
		t.Fatal(report, err)
	}
	for _, r := range report.Routes {
		if r.Outcome != "degraded" || r.Reason != "verification_budget_exhausted" {
			t.Fatal(r)
		}
	}
}

// A prober may finish after cancellation without returning the context error.
// The verifier still owns the shared budget and must refuse final publication.
type lateSuccessProbe struct{}

func (lateSuccessProbe) CheckRoute(ctx context.Context, _ edge.RouteProbe) error {
	<-ctx.Done()
	return nil
}

func TestPostApplyLateSuccessRestoresBeforeFinalReceipt(t *testing.T) {
	_, disk, process, base := harness()
	authority := &phaseAuthority{authority: base}
	evidence := &routeEvidence{}
	verifier := verificationFunc(func(ctx context.Context, p edge.Plan, artifact string) (edge.RouteVerification, error) {
		if p.Snapshot.Version == "old" {
			return edge.RouteVerification{BusinessVerified: true}, nil
		}
		if !authority.activated || authority.finalized || disk.j.State != domain.Verifying || !disk.j.ReceiptPending {
			t.Fatal("heads/receipt finalized before probe", disk.j)
		}
		plan := routePlan()
		plan.Snapshot.Version = p.Snapshot.Version
		plan.Runtime.Generation = p.Runtime.Generation
		return (edge.RouteVerifier{Probe: lateSuccessProbe{}, Evidence: evidence}).Verify(ctx, plan, artifact)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := edge.NewSupervisor(process, disk, disk, compiler{}, authority, verifier).Apply(ctx, "new")
	if ctx.Err() != nil {
		t.Fatal("outer apply deadline hid the shared-budget failure", ctx.Err())
	}
	if !errors.Is(err, edge.ErrRouteVerification) || authority.finalized || process.version != "old/g1" || result.State != "restored" || disk.j.State != domain.Restored || disk.j.ReceiptPending {
		t.Fatal("late success bypassed safe restoration", result, disk.j, err)
	}
	if result.Verification == nil || result.Verification.BusinessVerified || evidence.report.BusinessVerified || len(evidence.report.Routes) != 2 || evidence.report.ArtifactID == "" {
		t.Fatal("missing failed candidate evidence", result, evidence.report)
	}
	for _, route := range evidence.report.Routes {
		if route.Outcome != "degraded" || route.Reason != "verification_budget_exhausted" {
			t.Fatal("late nil callback recorded successful evidence", route)
		}
	}
}
