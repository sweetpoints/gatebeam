package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRoleReadinessIsIndependent(t *testing.T) {
	now := time.Now()
	s := New(func() time.Time { return now })
	for _, cap := range []string{Data, Management, ACME, Status, Query, GlobalJobs, LocalCleanup} {
		s.SetReady(cap, true)
	}
	s.SetReady(Query, false)
	s.SetReady(ACME, false)
	if !s.Live() || !s.Ready(Data) || !s.Ready(Management) || !s.Ready(Status) || s.Ready(Query) || s.Ready(ACME) {
		t.Fatal("independent role outage propagated")
	}
	s.BeginDrain(now.Add(time.Minute))
	if s.Ready(Data) || s.Accepts(GlobalJobs) || s.Accepts(Management) || !s.Accepts(LocalCleanup) || !s.Live() {
		t.Fatal("drain did not stop new work and retain cleanup")
	}
	s.BeginDrain(now.Add(time.Hour))
	now = now.Add(61 * time.Second)
	if s.Accepts(LocalCleanup) {
		t.Fatal("drain extended or cleanup ran beyond deadline")
	}
	if s.Ready("invented") || s.Accepts("invented") {
		t.Fatal("unknown capability allowed")
	}
	s.Stop()
	if s.Live() {
		t.Fatal("stopped process live")
	}
}
func TestMaintenanceDoesNotRewriteCapabilityHealth(t *testing.T) {
	s := New(time.Now)
	s.SetReady(Management, true)
	s.SetMaintenance(true)
	if s.Ready(Management) || s.Accepts(Management) || !s.Live() {
		t.Fatal("maintenance admission")
	}
	s.SetMaintenance(false)
	if !s.Ready(Management) {
		t.Fatal("maintenance destroyed underlying health")
	}
}

func TestProbeResultKeepsAdmissionAndFixedFailureClassTogether(t *testing.T) {
	const private = "owned-private-material-and-database-error"
	state := New(time.Now)
	state.SetReady(Data, true)
	for _, row := range []struct {
		err   error
		class string
	}{
		{nil, "ok"},
		{errors.New(private), "failed"},
		{errors.Join(errors.New(private), context.DeadlineExceeded), "deadline"},
		{context.Canceled, "cancelled"},
		{nil, "ok"},
	} {
		state.SetProbeResult(Management, row.err)
		snapshot := state.Snapshot()
		if snapshot.Ready[Management] != (row.err == nil) || snapshot.Details["probe_management"] != row.class || !snapshot.Ready[Data] {
			t.Fatal("probe result changed independent admission or lost its fixed class")
		}
		raw, err := json.Marshal(snapshot)
		if err != nil || strings.Contains(string(raw), private) {
			t.Fatal("raw probe error entered the health snapshot")
		}
	}
	state.SetProbeResult(private, nil)
	if _, exists := state.Snapshot().Details["probe_"+private]; exists || state.Ready(private) {
		t.Fatal("unknown probe capability was accepted")
	}
	state.SetMaintenance(true)
	state.SetProbeResult(Management, nil)
	if state.Ready(Management) || state.Snapshot().Ready[Management] {
		t.Fatal("a successful probe bypassed maintenance admission")
	}
}
