package probe

import (
	"context"
	"encoding/pem"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type bodyDeadlineProbe struct {
	address      netip.AddrPort
	childTimeout time.Duration
	headers      <-chan struct{}
}

func (p bodyDeadlineProbe) CheckRoute(ctx context.Context, route edge.RouteProbe) error {
	route.Address = p.address
	if p.childTimeout != 0 {
		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		defer cancel(nil)
		// This fixture tests cancellation while consuming the body. TLS setup
		// must finish first, including on software-emulated CI CPUs.
		go func() {
			select {
			case <-p.headers:
			case <-ctx.Done():
				return
			}
			timer := time.NewTimer(p.childTimeout)
			defer timer.Stop()
			select {
			case <-timer.C:
				cancel(context.DeadlineExceeded)
			case <-ctx.Done():
			}
		}()
	}
	return (HTTP{}).CheckRoute(ctx, route)
}

type bodyDeadlineEvidence struct{ report edge.RouteVerification }

func (e *bodyDeadlineEvidence) SaveRouteVerification(ctx context.Context, report edge.RouteVerification) error {
	e.report = report
	return ctx.Err()
}

func TestRouteVerificationRejectsTLSHeadersWithStalledBody(t *testing.T) {
	for _, test := range []struct {
		name         string
		childTimeout time.Duration
		reason       string
	}{
		{"route_body_timeout_before_shared_budget", 100 * time.Millisecond, "tls_or_route_probe_failed"},
		{"shared_budget_outer_context_alive", 0, "verification_budget_exhausted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			headers := make(chan struct{})
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Deliberately exceed the body budget before sending headers:
				// a timer started before TLS/headers would test the wrong phase.
				time.Sleep(250 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(headers)
				<-r.Context().Done()
			}))
			defer srv.Close()
			cert := srv.Certificate()
			trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			plan := edge.Plan{Snapshot: app.Snapshot{Version: "candidate", Sites: []app.Site{{ID: "site", Revision: 2, Config: app.SiteConfig{Enabled: true, Domains: []string{cert.DNSNames[0]}, DefaultTarget: app.TargetRef{ID: "backend"}, EntryCertificate: &app.MaterialRef{ID: "entry", Revision: 1}}}}, Targets: []app.Target{{ID: "backend", Revision: 3, Config: app.TargetConfig{Health: app.HealthPolicy{Enabled: true, Path: "/health"}}}}}, Runtime: edge.RuntimeState{Generation: "security-generation", Materials: map[string]edge.Material{"entry": {Revision: 1, CertificatePEM: trust}}}}
			probe := bodyDeadlineProbe{address: netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://")), childTimeout: test.childTimeout, headers: headers}
			evidence := &bodyDeadlineEvidence{}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			report, err := (edge.RouteVerifier{Probe: probe, Evidence: evidence}).Verify(ctx, plan, "candidate-artifact")
			select {
			case <-headers:
			default:
				t.Fatal("request failed before receiving real TLS 200 headers")
			}
			if ctx.Err() != nil {
				t.Fatal("outer deadline hid the probe failure", ctx.Err())
			}
			if !errors.Is(err, edge.ErrRouteVerification) || report.BusinessVerified || evidence.report.BusinessVerified || len(evidence.report.Routes) != 1 || evidence.report.ArtifactID != "candidate-artifact" {
				t.Fatalf("200 headers hid stalled response body: report=%+v evidence=%+v error=%v", report, evidence.report, err)
			}
			route := evidence.report.Routes[0]
			if route.Outcome != "degraded" || route.Reason != test.reason {
				t.Fatal("incorrect durable body deadline evidence", route)
			}
		})
	}
}
