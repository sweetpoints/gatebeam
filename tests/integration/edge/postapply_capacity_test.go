//go:build integration

package edge_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/probe"
	"io"
	"net"
	"net/http/httptrace"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type routeProbeMetrics struct {
	started, handshakes, firstBytes   atomic.Int64
	failureMu                         sync.Mutex
	failures                          []routeProbeFailure
	handshakeNanos, maxHandshakeNanos atomic.Int64
}

type ownedRouteProbe struct {
	address netip.AddrPort
	metrics *routeProbeMetrics
}

func (p ownedRouteProbe) CheckRoute(ctx context.Context, r edge.RouteProbe) error {
	// Only map the owned container's published port. Keep the production TLS
	// verifier, exact SNI/Host, trusted certificate and read-only route unchanged.
	r.Address = p.address
	p.metrics.started.Add(1)
	started := time.Now()
	var connected, tlsFailed, responseStarted atomic.Bool
	var connectionFailure, tlsFailure atomic.Pointer[string]
	var handshakeStart atomic.Pointer[time.Time]
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) {
			connected.Store(err == nil)
			if err != nil {
				classification := routeFailureClass(err)
				connectionFailure.Store(&classification)
			}
		},
		TLSHandshakeStart: func() { started := time.Now(); handshakeStart.Store(&started) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				tlsFailed.Store(true)
				classification := routeFailureClass(err)
				tlsFailure.Store(&classification)
				return
			}
			started := handshakeStart.Load()
			if started == nil {
				return
			}
			elapsed := time.Since(*started).Nanoseconds()
			p.metrics.handshakes.Add(1)
			p.metrics.handshakeNanos.Add(elapsed)
			for previous := p.metrics.maxHandshakeNanos.Load(); elapsed > previous; previous = p.metrics.maxHandshakeNanos.Load() {
				if p.metrics.maxHandshakeNanos.CompareAndSwap(previous, elapsed) {
					break
				}
			}
		},
		GotFirstResponseByte: func() { responseStarted.Store(true); p.metrics.firstBytes.Add(1) },
	})
	err := (probe.HTTP{}).CheckRoute(ctx, r)
	if err != nil {
		deadline, _ := ctx.Deadline()
		failure := routeProbeFailure{Host: r.Host, Path: r.Path, Elapsed: time.Since(started), Remaining: time.Until(deadline), Cancelled: errors.Is(ctx.Err(), context.Canceled), Deadline: errors.Is(ctx.Err(), context.DeadlineExceeded), Connected: connected.Load(), TLSFailed: tlsFailed.Load(), Response: responseStarted.Load(), ConnectionError: routeFailureValue(connectionFailure.Load()), TLSError: routeFailureValue(tlsFailure.Load())}
		p.metrics.failureMu.Lock()
		if len(p.metrics.failures) < 8 {
			p.metrics.failures = append(p.metrics.failures, failure)
		}
		p.metrics.failureMu.Unlock()
	}
	return err
}

type routeProbeFailure struct {
	Host, Path                                          string
	Elapsed, Remaining                                  time.Duration
	Cancelled, Deadline, Connected, TLSFailed, Response bool
	ConnectionError, TLSError                           string
}

func (m *routeProbeMetrics) logFailures(t *testing.T) {
	t.Helper()
	m.failureMu.Lock()
	defer m.failureMu.Unlock()
	for _, failure := range m.failures {
		t.Logf("failed route probe: %+v", failure)
	}
}

// Keep error details to fixed classes: transport errors may include addresses
// or request data and must never be printed directly.
func routeFailureClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return "certificate"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "other"
}
func routeFailureValue(value *string) string {
	if value == nil {
		return "none"
	}
	return *value
}

type routeEvidence struct{ saved edge.RouteVerification }

func (e *routeEvidence) SaveRouteVerification(_ context.Context, v edge.RouteVerification) error {
	e.saved = v
	return nil
}
func TestAffectedRouteVerificationBudget(t *testing.T) {
	lifetime := 180
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		lifetime = 420
	}
	f := setupLifetime(t, lifetime)
	cert, key := f.ca.leaf(t, "*.capacity.test", false)
	f.state.Materials["capacity-entry"] = edge.Material{Revision: 1, CertificatePEM: cert, KeyPEM: key}
	f.snapshot.Targets[0].Config.Health = app.HealthPolicy{Enabled: true, Path: "/health"}
	f.state.Health = map[string]edge.Health{"target": {TargetRevision: 1, Unhealthy: map[string]bool{}}}
	for i := 0; i < 50; i++ {
		config := app.SiteConfig{Enabled: true, Domains: []string{fmt.Sprintf("a%d.capacity.test", i), fmt.Sprintf("b%d.capacity.test", i)}, DefaultTarget: app.TargetRef{ID: "target"}, EntryCertificate: &app.MaterialRef{ID: "capacity-entry", Revision: 1}}
		for j := 0; j < 3; j++ {
			config.Routes = append(config.Routes, app.Route{Match: "prefix", Path: fmt.Sprintf("/route%d/", j), StripPrefix: true, Target: app.TargetRef{ID: "target"}})
		}
		f.snapshot.Sites = append(f.snapshot.Sites, app.Site{ID: fmt.Sprintf("site-%d", i), Revision: 1, Config: config})
	}
	f.start(t)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Read only this fixture's bounded structured access log. Never emit raw
		// server output, request identifiers, headers, bodies or certificate data.
		raw, err := exec.CommandContext(ctx, "docker", "exec", f.name, "tail", "-n", "450", "/tmp/access.log").Output()
		if err != nil {
			t.Log("route access status diagnostics unavailable")
			return
		}
		counts := map[int]int{}
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			var record struct {
				Status int `json:"status"`
			}
			if json.Unmarshal(line, &record) == nil && record.Status >= 100 && record.Status <= 599 {
				counts[record.Status]++
			}
		}
		t.Logf("owned route access status counts: %v", counts)
	})
	evidence := &routeEvidence{}
	metrics := &routeProbeMetrics{}
	start := time.Now()
	report, err := (edge.RouteVerifier{Probe: ownedRouteProbe{address: netip.MustParseAddrPort("127.0.0.1:" + f.port), metrics: metrics}, Evidence: evidence}).Verify(t.Context(), edge.Plan{Snapshot: f.snapshot, Runtime: f.state}, "owned-capacity-artifact")
	elapsed := time.Since(start)
	metrics.logFailures(t)
	t.Logf("route diagnostics: probes_started=%d TLS_handshakes_completed=%d responses_started=%d successful_handshake_total=%s successful_handshake_max=%s (sum includes concurrent handshakes)", metrics.started.Load(), metrics.handshakes.Load(), metrics.firstBytes.Load(), time.Duration(metrics.handshakeNanos.Load()), time.Duration(metrics.maxHandshakeNanos.Load()))
	emulated := os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm"
	if emulated {
		// Retain every original full-probe outcome even if a later batch fails.
		if directory := os.Getenv("GATEBEAM_ACCEPTANCE_REPORT_DIR"); directory != "" {
			original, e := json.Marshal(report)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(directory, "tls-full-route-verification.json"), append(original, '\n'), 0600); e != nil {
				t.Fatal(e)
			}
		}
		verified := 0
		for _, route := range report.Routes {
			if route.Outcome == "verified" {
				verified++
			}
		}
		if len(report.Routes) != 400 || !reflect.DeepEqual(evidence.saved, report) {
			t.Fatal("full route outcomes were not persisted", len(report.Routes))
		}
		if verified == 400 {
			if err != nil || !report.BusinessVerified {
				t.Fatal("completed report rejected", err)
			}
		} else {
			if !errors.Is(err, edge.ErrRouteVerification) || report.BusinessVerified {
				t.Fatal("incomplete route verification was accepted", err, report.BusinessVerified)
			}
			for _, route := range report.Routes {
				if route.Outcome != "verified" && (route.Outcome != "degraded" || route.Reason != "verification_budget_exhausted") {
					t.Fatal("full probe failed for a reason other than budget exhaustion", route)
				}
			}
		}
		measurement := map[string]any{"execution": "software-emulated-vm", "policy": "software-functional-v1", "performance_certification": "not-certified", "routes": 400, "verified": verified, "elapsed_seconds": elapsed.Seconds(), "budget_seconds": 5, "target_met": err == nil && report.BusinessVerified}
		data, e := json.Marshal(measurement)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("SOFTWARE_TLS_PERFORMANCE %s", data)
		measurement["full_routes"] = report.Routes
		measurement["full_business_verified"] = report.BusinessVerified
		measurement["full_failed"] = err != nil
		persist := func() {
			t.Helper()
			data, e := json.Marshal(measurement)
			if e != nil {
				t.Fatal(e)
			}
			if directory := os.Getenv("GATEBEAM_ACCEPTANCE_REPORT_DIR"); directory != "" {
				if e = os.WriteFile(filepath.Join(directory, "tls-performance.json"), append(data, '\n'), 0600); e != nil {
					t.Fatal(e)
				}
			}
		}
		persist()

		// Keep the full applied configuration. Select only one site's eight probes
		// per call to the unmodified production verifier and its five-second budget.
		batchCtx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		defer cancel()
		seen := map[string]bool{}
		for _, site := range f.snapshot.Sites {
			plan := edge.Plan{Snapshot: f.snapshot, Runtime: f.state}
			plan.Snapshot.Sites = []app.Site{site}
			saved := &routeEvidence{}
			batch, e := (edge.RouteVerifier{Probe: ownedRouteProbe{address: netip.MustParseAddrPort("127.0.0.1:" + f.port), metrics: metrics}, Evidence: saved}).Verify(batchCtx, plan, "owned-capacity-artifact")
			if e != nil || !batch.BusinessVerified || len(batch.Routes) != 8 || !reflect.DeepEqual(saved.saved, batch) {
				metrics.logFailures(t)
				t.Fatalf("site functional route proof failed: site=%s err=%v report=%+v", site.ID, e, batch)
			}
			for _, route := range batch.Routes {
				key := route.SiteID + "|" + route.Host + "|" + route.Route
				if seen[key] || route.Outcome != "verified" || route.Host != route.SNI {
					t.Fatal("duplicate or invalid route evidence", route)
				}
				seen[key] = true
			}
		}
		if len(seen) != 400 {
			t.Fatal("functional coverage incomplete", len(seen))
		}
		measurement["functional_verified"] = len(seen)
		measurement["functional_batches"] = 50
		persist()
		t.Logf("software functional coverage: all 400 routes verified on unchanged full configuration; 50 batches of 8, production budget=5s, suite budget=300s; native performance not certified")
		return
	}
	if err != nil || !report.BusinessVerified || len(report.Routes) != 400 || len(evidence.saved.Routes) != 400 {
		outcomes := map[string]int{}
		for _, route := range report.Routes {
			outcomes[route.Outcome+"/"+route.Reason]++
		}
		t.Fatalf("route budget failed: elapsed=%s routes=%d verified=%t outcomes=%v error=%v", elapsed, len(report.Routes), report.BusinessVerified, outcomes, err)
	}
	for _, route := range report.Routes {
		if route.Outcome != "verified" || route.Host != route.SNI {
			t.Fatal("route proof incomplete", route)
		}
	}
	t.Logf("actual native TLS/read-only probes: sites=50 domains=100 locations=400 concurrency=8 fixed_budget=5s elapsed=%s nativeCPU=.5 nativeMemory=128MiB; every outcome persisted", elapsed)
}
