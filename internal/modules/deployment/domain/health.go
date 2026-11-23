package domain

import (
	"errors"
	"time"
)

// HealthThresholds and MemberHealth are pure policies. A sequence is allocated
// before I/O; equal/older results cannot consume thresholds a second time.
type HealthThresholds struct{ Failures, Successes int }
type MemberHealth struct {
	Sequence  int64 `json:"sequence"`
	Failures  int   `json:"failures"`
	Successes int   `json:"successes"`
	Unhealthy bool  `json:"unhealthy"`
}

func (s MemberHealth) Observe(sequence int64, healthy bool, p HealthThresholds) (MemberHealth, bool) {
	if sequence <= s.Sequence {
		return s, false
	}
	if p.Failures <= 0 {
		p.Failures = 3
	}
	if p.Successes <= 0 {
		p.Successes = 2
	}
	before := s.Unhealthy
	s.Sequence = sequence
	if healthy {
		s.Failures = 0
		if s.Successes < p.Successes {
			s.Successes++
		}
		if s.Successes >= p.Successes {
			s.Unhealthy = false
		}
	} else {
		s.Successes = 0
		if s.Failures < p.Failures {
			s.Failures++
		}
		if s.Failures >= p.Failures {
			s.Unhealthy = true
		}
	}
	return s, before != s.Unhealthy
}

// ProbeBinding is the immutable authority a sample started with. Current state
// compares every dimension after I/O; revisions alone do not protect a DNS or
// manual-publication race. No timestamp supplied by a network peer is trusted.
type ProbeBinding struct {
	ReleaseID                          string
	TargetRevision                     int64
	MemberFingerprint, ResolutionToken string
	Sequence                           int64
}

func (current ProbeBinding) Accepts(started ProbeBinding, resultSequence int64) bool {
	return current.ReleaseID != "" && current == started && resultSequence == current.Sequence+1
}

const ProbeConcurrency = 8
const MaxHealthBudget = 65 * time.Second

var ErrHealthCapacity = errors.New("health probe capacity exceeds 65 seconds; reduce member/DNS endpoints or health timeout")

// HealthBudget admits only an atomic group that fits eight bounded probe
// workers plus five seconds of DNS/persistence margin. Unsupported groups are
// rejected before activation instead of remaining indefinitely optimistically live.
func HealthBudget(endpoints int, timeout time.Duration) (time.Duration, error) {
	if endpoints < 0 || endpoints > 10000 || timeout <= 0 || timeout > 60*time.Second {
		return 0, ErrHealthCapacity
	}
	budget := time.Duration((endpoints+ProbeConcurrency-1)/ProbeConcurrency)*timeout + 5*time.Second
	if budget > MaxHealthBudget {
		return 0, ErrHealthCapacity
	}
	if budget < 30*time.Second {
		budget = 30 * time.Second
	}
	return budget, nil
}
