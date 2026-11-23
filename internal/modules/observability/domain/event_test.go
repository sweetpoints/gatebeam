package domain

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestTypedObservationValidation(t *testing.T) {
	base := Event{SiteID: "11111111-1111-4111-8111-111111111111", RequestID: "0123456789abcdef0123456789abcdef", Time: time.Date(2026, 11, 7, 0, 0, 0, 0, time.FixedZone("offset", 3600)), Route: "0", Method: "GET", Status: 200, Bytes: 20}
	e, err := NewEvent(base, .012)
	if err != nil || e.Micros != 12000 || e.Time.Location() != time.UTC {
		t.Fatal(e, err)
	}
	for _, duration := range []float64{-1, 86400.1, math.NaN(), math.Inf(1)} {
		if _, err := NewEvent(base, duration); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe numeric duration accepted", duration, err)
		}
	}
	for _, mutate := range []func(*Event){func(e *Event) { e.SiteID = "unknown" }, func(e *Event) { e.RequestID = "secret" }, func(e *Event) { e.Route = "secret" }, func(e *Event) { e.Status = 600 }, func(e *Event) { e.Bytes = -1 }, func(e *Event) { e.Bytes = 1 << 51 }, func(e *Event) { e.Time = time.Time{} }, func(e *Event) { e.ConfigID = "secret" }, func(e *Event) { e.TargetID = "secret" }, func(e *Event) { e.PathPattern = "/safe?token=secret" }, func(e *Event) { e.UpstreamOutcome = "secret" }, func(e *Event) { e.RateRequest = "secret" }, func(e *Event) { e.PathPattern = "/" + strings.Repeat("a", 2048) }} {
		candidate := base
		mutate(&candidate)
		if _, err := NewEvent(candidate, 1); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid typed observation accepted", err)
		}
	}
	base.PathPattern = "/" + strings.Repeat("a", 2047)
	base.Method = "arbitrary-method"
	e, err = NewEvent(base, 86400)
	if err != nil || e.Method != "OTHER" || e.Micros != 86400000000 {
		t.Fatal("canonical limit observation rejected", e, err)
	}
}
