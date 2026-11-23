package lego

import (
	"context"
	"time"
)

// HTTPChallenges coordinates standard HTTP-01 files across the current serving
// set. It changes no ACME protocol messages and exposes no enrollment endpoint.
type HTTPChallenges interface {
	PrepareCurrent(context.Context, string, string, string) error
	Ready(context.Context, string) (bool, error)
	Cleanup(context.Context, string) error
}
type coordinatedHTTP struct {
	ctx         context.Context
	owner       string
	coordinator HTTPChallenges
}

func (p coordinatedHTTP) Present(_ context.Context, _ string, token, keyAuth string) error {
	if e := p.coordinator.PrepareCurrent(p.ctx, p.owner, token, keyAuth); e != nil {
		return e
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		ready, e := p.coordinator.Ready(p.ctx, p.owner)
		if e != nil {
			return e
		}
		if ready {
			return nil
		}
		select {
		case <-p.ctx.Done():
			return p.ctx.Err()
		case <-deadline.C:
			return ErrACME
		case <-tick.C:
		}
	}
}

// Retire all tokens only when Obtain has finished. Lego may validate several
// names concurrently; one token's cleanup must not retire its siblings early.
func (p coordinatedHTTP) CleanUp(context.Context, string, string, string) error { return nil }
