package domain

import (
	"testing"
	"time"
)

func TestMergedHistogramUsesPopulationNotBucketPercentiles(t *testing.T) {
	h := Histogram{}
	for range 100 {
		h.Add(1000)
	}
	slow := Histogram{}
	slow.Add(30000000)
	for i, n := range slow {
		h[i] += n
	}
	if h.Percentile(.95) != 1000 {
		t.Fatal("percentile did not use merged population")
	}
	events := []Event{{SiteID: "a", Route: "1", Method: "GET", Time: time.Unix(60, 0), Micros: 1000, Status: 200}, {SiteID: "a", Route: "1", Method: "GET", Time: time.Unix(61, 0), Micros: 25000, Status: 204}}
	b := Aggregate(events)
	if len(b) != 1 || b[0].Count != 2 || b[0].Micros != 26000 {
		t.Fatal(b)
	}
}

func TestFixedRouteIdentityIncludesCompilerConfiguration(t *testing.T) {
	events := []Event{{SiteID: "a", Route: "0", ConfigID: "v1", Method: "GET", Time: time.Unix(60, 0), Micros: 1000, Status: 200}, {SiteID: "a", Route: "0", ConfigID: "v2", Method: "GET", Time: time.Unix(61, 0), Micros: 25000, Status: 200}}
	b := Aggregate(events)
	if len(b) != 2 {
		t.Fatal("reused route index merged across configurations", b)
	}
}
