package preflight

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	"net/netip"
	"testing"
)

type siteSource struct{ site app.Site }

func (s siteSource) Site(context.Context, string) (app.Site, error) { return s.site, nil }

type countingProbe struct {
	calls int
	p     health.Probe
}

func (s *countingProbe) Check(_ context.Context, p health.Probe) error {
	s.calls++
	s.p = p
	return nil
}
func TestPreflightPreservesAOPAndMTLS(t *testing.T) {
	for _, site := range []app.Site{{Config: app.SiteConfig{Domains: []string{"business.example"}, Cloudflare: app.CFPolicy{Mode: "proxied", RequireOriginPull: true}}}, {Config: app.SiteConfig{Domains: []string{"business.example"}, ClientVerification: app.ClientVerification{Mode: "required"}}}} {
		p := &countingProbe{}
		svc := New(siteSource{site}, p, nil)
		report, e := svc.Check(context.Background(), "s", EntryAddress{Role: "new", Mode: "direct", Address: netip.MustParseAddrPort("203.0.113.8:443"), Path: "/health"})
		if e != nil || report.Ready || p.calls != 0 || report.Result != "policy_refused" {
			t.Fatal(report, e, p.calls)
		}
	}
}
func TestPreflightPinsHostSNIAndReadOnlyPath(t *testing.T) {
	p := &countingProbe{}
	svc := New(siteSource{app.Site{ID: "s", Revision: 3, Config: app.SiteConfig{Domains: []string{"business.example"}}}}, p, nil)
	report, e := svc.Check(context.Background(), "s", EntryAddress{Role: "old", Mode: "direct", Address: netip.MustParseAddrPort("203.0.113.8:443"), Path: "/health"})
	if e != nil || !report.Ready || p.p.HTTPHost != "business.example" || p.p.TLSName != "business.example" || p.p.Path != "/health" {
		t.Fatal(report, e, p.p)
	}
}
func TestPreflightRejectsControlAddress(t *testing.T) {
	p := &countingProbe{}
	svc := New(siteSource{}, p, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	for _, ip := range []string{"127.0.0.1:443", "169.254.169.254:443", "10.0.0.5:443", "[fd00:ec2::254]:443"} {
		if _, e := svc.Check(context.Background(), "s", EntryAddress{Role: "new", Mode: "direct", Address: netip.MustParseAddrPort(ip), Path: "/"}); e == nil {
			t.Fatal("accepted", ip)
		}
	}
}

func TestPreflightMissingProtectedConfigurationRefusesPrivateEntry(t *testing.T) {
	probe := &countingProbe{}
	svc := New(siteSource{app.Site{Config: app.SiteConfig{Domains: []string{"business.example"}}}}, probe, nil)
	if _, e := svc.Check(context.Background(), "s", EntryAddress{Role: "new", Mode: "direct", Address: netip.MustParseAddrPort("10.0.0.5:443"), Path: "/"}); e == nil || probe.calls != 0 {
		t.Fatal("unconfigured private control protection accepted", e)
	}
}

func TestPreflightChecksExplicitTLSPort(t *testing.T) {
	probe := &countingProbe{}
	svc := New(siteSource{app.Site{ID: "s", Revision: 1, Config: app.SiteConfig{Domains: []string{"business.example"}}}}, probe, nil)
	report, e := svc.Check(context.Background(), "s", EntryAddress{Role: "new", Mode: "direct", Address: netip.MustParseAddrPort("203.0.113.8:8443"), Path: "/health"})
	if e != nil || !report.Ready || probe.p.Address.Port() != 8443 {
		t.Fatal("explicit entry TLS port ignored", report, e)
	}
}
