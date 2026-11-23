// Package lifecycle tracks process admission separately from dependency health.
package lifecycle

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	Data         = "data"
	Management   = "management"
	ACME         = "acme"
	Status       = "status"
	Query        = "query"
	GlobalJobs   = "global-jobs"
	LocalCleanup = "local-cleanup"
)

var capabilities = []string{Data, Management, ACME, Status, Query, GlobalJobs, LocalCleanup}

type Snapshot struct {
	Details  map[string]string `json:"details,omitempty"`
	Live     bool              `json:"live"`
	Mode     string            `json:"mode"`
	Ready    map[string]bool   `json:"ready"`
	Deadline time.Time         `json:"deadline,omitempty"`
}
type State struct {
	details                        map[string]string
	mu                             sync.RWMutex
	now                            func() time.Time
	ready                          map[string]bool
	stopped, maintenance, draining bool
	deadline                       time.Time
	drain                          chan struct{}
}

func New(now func() time.Time) *State {
	if now == nil {
		now = time.Now
	}
	return &State{now: now, ready: map[string]bool{}, drain: make(chan struct{})}
}
func known(cap string) bool {
	for _, c := range capabilities {
		if c == cap {
			return true
		}
	}
	return false
}
func (s *State) SetReady(cap string, ready bool) {
	if !known(cap) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready[cap] = ready
}

// SetProbeResult records only a fixed result class, never the probe's error
// text. The existing readiness predicate and maintenance/drain rules remain the
// sole admission decisions; probe details explain the last completed check.
func (s *State) SetProbeResult(cap string, err error) {
	if !known(cap) {
		return
	}
	class := "ok"
	if err != nil {
		class = "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			class = "deadline"
		} else if errors.Is(err, context.Canceled) {
			class = "cancelled"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready[cap] = err == nil
	if s.details == nil {
		s.details = map[string]string{}
	}
	s.details["probe_"+cap] = class
}

func (s *State) Live() bool { s.mu.RLock(); defer s.mu.RUnlock(); return !s.stopped }
func (s *State) Ready(cap string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return known(cap) && !s.stopped && !s.maintenance && !s.draining && s.ready[cap]
}
func (s *State) Accepts(cap string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !known(cap) || s.stopped {
		return false
	}
	if s.draining {
		return cap == LocalCleanup && s.now().Before(s.deadline)
	}
	if s.maintenance {
		return cap == LocalCleanup
	}
	return s.ready[cap]
}
func (s *State) SetMaintenance(value bool) { s.mu.Lock(); defer s.mu.Unlock(); s.maintenance = value }
func (s *State) BeginDrain(deadline time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.draining {
		s.draining = true
		s.deadline = deadline
		close(s.drain)
	} else if deadline.Before(s.deadline) {
		s.deadline = deadline
	}
}
func (s *State) Draining() <-chan struct{} { return s.drain }
func (s *State) Stop()                     { s.mu.Lock(); defer s.mu.Unlock(); s.stopped = true }
func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mode := "serving"
	if s.maintenance {
		mode = "maintenance"
	}
	if s.draining {
		mode = "draining"
	}
	if s.stopped {
		mode = "stopped"
	}
	ready := map[string]bool{}
	for cap := range s.ready {
		ready[cap] = !s.stopped && !s.maintenance && !s.draining && s.ready[cap]
	}
	details := map[string]string{}
	for k, v := range s.details {
		details[k] = v
	}
	return Snapshot{Details: details, Live: !s.stopped, Mode: mode, Ready: ready, Deadline: s.deadline}
}

type stateKey struct{}

func WithState(ctx context.Context, s *State) context.Context {
	return context.WithValue(ctx, stateKey{}, s)
}
func FromContext(ctx context.Context) *State { s, _ := ctx.Value(stateKey{}).(*State); return s }

func (s *State) SetDetail(key, value string) {
	switch key {
	case "management_config_digest", "artifact_id", "generation", "tls_renewal", "tls_renewal_stage":
	default:
		return
	}
	if len(value) > 256 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.details == nil {
		s.details = map[string]string{}
	}
	s.details[key] = value
}
