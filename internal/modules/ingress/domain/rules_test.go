package domain

import "testing"

func TestSiteRules(t *testing.T) {
	c := SiteConfig{Enabled: true, Domains: []string{" EXAMPLE.Test. "}, Routes: []Route{{Match: "prefix", Path: "/", Target: TargetRef{ID: "00000000-0000-4000-8000-000000000001"}}, {Match: "prefix", Path: "/api", StripPrefix: true, Target: TargetRef{ID: "00000000-0000-4000-8000-000000000001"}}, {Match: "exact", Path: "/api/item", Target: TargetRef{ID: "00000000-0000-4000-8000-000000000001"}}}}
	if e := c.Normalize(); e != nil {
		t.Fatal(e)
	}
	if c.Domains[0] != "example.test" || c.MatchRoute("/api/item").Match != "exact" || c.MatchRoute("/api/list").Path != "/api" {
		t.Fatal(c)
	}
	for _, h := range []string{"*.test", "https://test", "x\ntest", "foo_bar.test"} {
		if _, e := Host(h); e == nil {
			t.Fatal(h)
		}
	}
	c.Routes[0].Match = "regex"
	if c.Normalize() == nil {
		t.Fatal("regex accepted")
	}
}
func TestTLSNeverPretendsReady(t *testing.T) {
	r := MaterialRef{ID: "00000000-0000-4000-8000-000000000001", Revision: 1, Status: "unavailable"}
	c := TargetConfig{Name: "tls", Protocol: "https", Members: []TargetMember{{Address: "connect.internal", Port: 443, Weight: 1, TLSName: "verify.internal"}}, AllowedNetworks: []string{"10.0.0.0/8"}, TLSNameMode: "member", HTTPHost: "business.example", Trust: &r}
	if e := c.Normalize(); e != nil {
		t.Fatal(e)
	}
	if c.Ready() != ErrUnavailable || c.Members[0].Address == c.Members[0].TLSName || c.HTTPHost == c.Members[0].TLSName {
		t.Fatal(c)
	}
	c.Trust.Status = "ready"
	if c.Normalize() == nil {
		t.Fatal("fake ready certificate")
	}
}
func TestBoundsAndPolicyRules(t *testing.T) {
	for _, c := range []SiteConfig{{Enabled: true, Domains: []string{"a.test", "A.test"}}, {Enabled: true, Domains: []string{"a.test"}, Rate: RatePolicy{Burst: -1}}, {Enabled: true, Domains: []string{"a.test"}, ClientVerification: ClientVerification{Mode: "required"}}, {Enabled: true, Domains: []string{"a.test"}, Routes: []Route{{Match: "exact", Path: "/", StripPrefix: true}}}} {
		if c.Normalize() == nil {
			t.Fatal(c)
		}
	}
	g := SiteGroup{ID: "secret-bearer", Name: "group"}
	if g.Normalize() == nil {
		t.Fatal("non UUID")
	}
}

func TestAggregateDraftTransition(t *testing.T) {
	published := SiteConfig{Enabled: true, Domains: []string{"published.test"}}
	s := Site{ID: "00000000-0000-4000-8000-000000000001", Revision: 3, Draft: published, PublishedRevision: 2, Published: &published}
	next := SiteConfig{Enabled: true, Domains: []string{"next.test"}, Maintenance: MaintenancePolicy{Enabled: true}}
	if e := s.ReviseDraft(next, 2); e != ErrConflict {
		t.Fatal("stale accepted", e)
	}
	if e := s.ReviseDraft(next, 3); e != nil {
		t.Fatal(e)
	}
	if s.Revision != 4 || s.PublishedRevision != 2 || s.Published.Maintenance.Enabled {
		t.Fatal("published changed", s)
	}
	if e := s.Remove(4); e != ErrReferenced {
		t.Fatal("live site removed", e)
	}
	s.Published = nil
	s.PublishedRevision = 0
	if e := s.Remove(4); e != nil || !s.Deleted {
		t.Fatal("draft not tombstoned", e)
	}
	if e := s.ReviseDraft(next, 4); e != ErrNotFound {
		t.Fatal("tombstone editable", e)
	}
}
func TestTargetAggregateIndependentRevision(t *testing.T) {
	cfg := TargetConfig{Name: "upstream", Protocol: "http", Members: []TargetMember{{Address: "app.internal", Port: 8080, Weight: 1}}, AllowedNetworks: []string{"10.0.0.0/8"}}
	published := cfg
	target := TargetGroup{ID: "00000000-0000-4000-8000-000000000001", Revision: 1, Config: cfg, PublishedRevision: 1, Published: &published}
	cfg.Name = "new"
	if e := target.Revise(cfg, 0); e != ErrConflict {
		t.Fatal(e)
	}
	if e := target.Revise(cfg, 1); e != nil {
		t.Fatal(e)
	}
	if target.Revision != 2 || target.Published.Name != "upstream" {
		t.Fatal("target publication mutated", target)
	}
}

func TestDraftNormalizationDoesNotMutatePublishedSlices(t *testing.T) {
	published := SiteConfig{Enabled: true, Domains: []string{"Published.Test"}}
	s := Site{Revision: 1, PublishedRevision: 1, Published: &published, Draft: published}
	next := published
	if e := s.ReviseDraft(next, 1); e != nil {
		t.Fatal(e)
	}
	if s.Published.Domains[0] != "Published.Test" {
		t.Fatal("draft normalization mutated published slice")
	}
}

func TestConnectionIPv6SeparateFromTLSAndHTTPNames(t *testing.T) {
	cfg := TargetConfig{Name: "ipv6 TLS", Protocol: "https", Members: []TargetMember{{Address: " FD00:0:0:0:0:0:0:1 ", Port: 443, Weight: 1, TLSName: "verify.internal"}}, HTTPHost: "business.example.test", TLSNameMode: "member", Trust: &MaterialRef{ID: "00000000-0000-4000-8000-000000000001", Revision: 1, Status: "unavailable"}, AllowedNetworks: []string{"fd00::/64"}}
	if e := cfg.Normalize(); e != nil {
		t.Fatal("IPv6 connection rejected", e)
	}
	m := cfg.Members[0]
	if m.Address != "fd00::1" || m.TLSName != "verify.internal" || cfg.HTTPHost != "business.example.test" {
		t.Fatal("connection/TLS/HTTP fields conflated", cfg)
	}
	for _, address := range []string{"[fd00::1]", "fd00::1%en0", "fd00::zz", "fd00::1:443:extra"} {
		bad := cfg.Clone()
		bad.Members[0].Address = address
		if bad.Normalize() == nil {
			t.Fatal("invalid or zoned connection accepted", address)
		}
	}
}

func TestHealthRuntimeDefaults(t *testing.T) {
	c := TargetConfig{Name: "health", Protocol: "http", Members: []TargetMember{{Address: "10.0.0.2", Port: 80, Weight: 1}}, AllowedNetworks: []string{"10.0.0.0/8"}}
	if e := c.Normalize(); e != nil {
		t.Fatal(e)
	}
	if c.Health.IntervalSeconds != 5 || c.Health.TimeoutSeconds != 2 || c.Health.UnhealthyThreshold != 3 || c.Health.HealthyThreshold != 2 {
		t.Fatalf("wrong runtime defaults %+v", c.Health)
	}
}

func TestVerifyOnlyModeRequiresExplicitMTLSAndSurvivesDraft(t *testing.T) {
	ref := MaterialRef{ID: "00000000-0000-4000-8000-000000000001", Revision: 1, Status: "unavailable"}
	cfg := TargetConfig{Name: "private native", Protocol: "https", Members: []TargetMember{{Address: "10.0.0.2", Port: 443, Weight: 1, TLSName: "a.internal.test"}}, TLSNameMode: "member", TLSServerNameMode: "verify_only", Trust: &ref, AllowedNetworks: []string{"10.0.0.0/24"}}
	if cfg.Normalize() == nil {
		t.Fatal("verify-only without client identity accepted")
	}
	cfg.ClientCertificate = &ref
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	cfg.TLSServerNameMode = "disable_verify"
	if cfg.Normalize() == nil {
		t.Fatal("unknown TLS mode accepted")
	}
}
