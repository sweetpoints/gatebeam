package domain

import (
	"math"
	"time"
)

// Histogram bounds are microseconds. The last bound includes the maximum
// accepted request duration; counts are noncumulative and can be added exactly.
var Bounds = [12]int64{1000, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000, 5000000, 30000000, 86400000000}

type Histogram [12]int64

func (h *Histogram) Add(v int64) {
	for i, b := range Bounds {
		if v <= b {
			h[i]++
			return
		}
	}
}
func (h Histogram) Percentile(q float64) int64 {
	var total int64
	for _, n := range h {
		total += n
	}
	if total == 0 || q <= 0 || q > 1 {
		return 0
	}
	target := int64(math.Ceil(float64(total) * q))
	var n int64
	for i, v := range h {
		n += v
		if n >= target {
			return Bounds[i]
		}
	}
	return 0
}

type Bucket struct {
	Minute                time.Time
	SiteID, Route, Method string
	ConfigID              string
	StatusClass           int
	Count, Micros, Bytes  int64
	Histogram             Histogram
}

func Aggregate(events []Event) []Bucket {
	type key struct {
		minute              int64
		site, route, method string
		config              string
		status              int
	}
	out := []Bucket{}
	index := map[key]int{}
	for _, e := range events {
		k := key{e.Time.Unix() / 60, e.SiteID, e.Route, e.Method, e.ConfigID, e.Status / 100}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, Bucket{Minute: e.Time.Truncate(time.Minute), SiteID: e.SiteID, Route: e.Route, Method: e.Method, ConfigID: e.ConfigID, StatusClass: e.Status / 100})
		}
		v := &out[i]
		v.Count++
		v.Micros += e.Micros
		v.Bytes += e.Bytes
		v.Histogram.Add(e.Micros)
	}
	return out
}

type Object struct {
	NodeID                      string
	SchemaVersion               int
	Key, Checksum, SiteID, Hour string
	Rows, Bytes                 int64
	MinTime, MaxTime            time.Time
}
type Batch struct {
	NodeID string
	// LagKnown distinguishes a measured timestamp or drained backlog from an
	// advancing malformed-only batch whose remaining backlog has unknown age.
	LagKnown                      bool
	LagSeconds                    int64
	ID, SegmentID, SourceChecksum string
	Anchor                        string
	Start, End                    int64
	Dropping                      bool
	Invalid, Schema, Oversize     int64
	Objects                       []Object
	Buckets                       []Bucket
}
