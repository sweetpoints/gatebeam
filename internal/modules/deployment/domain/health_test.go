package domain

import (
	"testing"
	"time"
)

func TestHealthThresholdsAndOrdering(t *testing.T) {
	p := HealthThresholds{}
	s := MemberHealth{}
	for i := int64(1); i <= 2; i++ {
		var changed bool
		s, changed = s.Observe(i, false, p)
		if changed || s.Unhealthy {
			t.Fatal("premature failure", s)
		}
	}
	s, changed := s.Observe(3, false, p)
	if !changed || !s.Unhealthy {
		t.Fatal("third failure must disable", s)
	}
	old := s
	s, changed = s.Observe(2, true, p)
	if changed || s != old {
		t.Fatal("old result changed state")
	}
	s, changed = s.Observe(4, true, p)
	if changed || !s.Unhealthy {
		t.Fatal("premature recovery")
	}
	s, changed = s.Observe(5, true, p)
	if !changed || s.Unhealthy {
		t.Fatal("second success must restore")
	}
}

func TestProbeBindingRejectsPublicationMemberDNSAndSequenceChanges(t *testing.T) {
	current := ProbeBinding{ReleaseID: "current", TargetRevision: 2, MemberFingerprint: "member-port-host-sni", ResolutionToken: "dns-2", Sequence: 7}
	if !current.Accepts(current, 8) {
		t.Fatal("current sample rejected")
	}
	variants := []ProbeBinding{current, current, current, current, current}
	variants[0].ReleaseID = "old"
	variants[1].TargetRevision = 1
	variants[2].MemberFingerprint = "replaced-member"
	variants[3].ResolutionToken = "dns-1"
	variants[4].Sequence = 6
	for _, old := range variants {
		if current.Accepts(old, 8) {
			t.Fatalf("stale binding accepted %+v", old)
		}
	}
	if current.Accepts(current, 7) || current.Accepts(current, 9) {
		t.Fatal("duplicate or unallocated sequence accepted")
	}
}

func TestHealthBudgetRespectsExplicitTimeoutAndCapacity(t *testing.T) {
	for _, tc := range []struct {
		endpoints, seconds int
		want               time.Duration
		reject             bool
	}{{1, 2, 30 * time.Second, false}, {8, 60, 65 * time.Second, false}, {100, 2, 31 * time.Second, false}, {240, 2, 65 * time.Second, false}, {241, 2, 0, true}, {9, 60, 0, true}} {
		got, e := HealthBudget(tc.endpoints, time.Duration(tc.seconds)*time.Second)
		if (e != nil) != tc.reject || got != tc.want {
			t.Fatal(tc, got, e)
		}
	}
}
