package domain

import "testing"

func TestTransitionsCoalesceAndFenceOldSources(t *testing.T) {
	i := Incident{}
	for _, tc := range []struct {
		version int64
		state   string
		changed bool
	}{{1, "firing", true}, {1, "resolved", false}, {2, "firing", false}, {3, "resolved", true}, {2, "firing", false}, {4, "resolved", false}, {5, "firing", true}} {
		changed := i.Observe(tc.version, tc.state)
		if changed != tc.changed {
			t.Fatalf("version %d changed=%v", tc.version, changed)
		}
	}
}
func TestMessageNeverRendersRawSource(t *testing.T) {
	e := Event{Kind: "ingestion_lag", State: "firing", Message: "password=SECRET", ResourceID: "SECRET", LagSeconds: 123}
	if got := e.Render(); got != "Gatebeam: ingestion lag firing; ingestion lag 123 seconds" {
		t.Fatal(got)
	}
}
