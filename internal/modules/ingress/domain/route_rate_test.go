package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRouteRateAdditionalAndCloned(t *testing.T) {
	c := SiteConfig{Domains: []string{"a.test"}, Routes: []Route{{Match: "prefix", Path: "/a", Target: TargetRef{ID: "00000000-0000-0000-0000-000000000001"}, Rate: &RatePolicy{RequestsPerSecond: 1}}}}
	if e := c.Normalize(); e != nil {
		t.Fatal(e)
	}
	d := c.Clone()
	d.Routes[0].Rate.RequestsPerSecond = 9
	if c.Routes[0].Rate.RequestsPerSecond != 1 {
		t.Fatal("rate alias")
	}
	picked := c.MatchRoute("/a/b")
	picked.Rate.RequestsPerSecond = 7
	if c.Routes[0].Rate.RequestsPerSecond != 1 {
		t.Fatal("selected route rate aliases configuration")
	}
	c.Routes[0].Rate.RequestsPerSecond = -1
	if c.Normalize() == nil {
		t.Fatal("invalid rate accepted")
	}
	b, _ := json.Marshal(Route{Path: "/"})
	if strings.Contains(string(b), "rate") {
		t.Fatal("omitted rate changed canonical bytes")
	}
}
