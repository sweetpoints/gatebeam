package composition

import (
	"context"
	"errors"
	"gatebeam/internal/platform/lifecycle"
	"sync"
)

var workerComponentNames = []string{"certificates", "local-logs", "history", "archive", "notification", "backup"}

type workerComponents struct {
	mu    sync.RWMutex
	ready map[string]bool
}
type workerComponentKey struct{}
type workerComponentRef struct {
	all  *workerComponents
	name string
}

func newWorkerComponents() *workerComponents {
	s := &workerComponents{ready: map[string]bool{}}
	for _, name := range workerComponentNames {
		s.ready[name] = false
	}
	return s
}
func withWorkerComponent(ctx context.Context, s *workerComponents, name string) context.Context {
	return context.WithValue(ctx, workerComponentKey{}, workerComponentRef{s, name})
}
func workerComponentReady(ctx context.Context, ready bool) {
	r, ok := ctx.Value(workerComponentKey{}).(workerComponentRef)
	if !ok || r.name == "" {
		return
	}
	r.all.mu.Lock()
	defer r.all.mu.Unlock()
	r.all.ready[r.name] = ready
}
func (s *workerComponents) readyError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, name := range workerComponentNames {
		if !s.ready[name] {
			return errors.New("worker component unavailable")
		}
	}
	return nil
}

// Readiness represents the whole role for activation/upgrade. Admission remains
// independent per running component, so an R2 outage cannot starve local queries.
func workerAdmission(ctx context.Context, cap string) (bool, bool) {
	if cap != lifecycle.GlobalJobs {
		return false, false
	}
	if _, ok := ctx.Value(workerComponentKey{}).(workerComponentRef); !ok {
		return false, false
	}
	state := lifecycle.FromContext(ctx)
	if state == nil {
		return true, true
	}
	snapshot := state.Snapshot()
	return snapshot.Live && snapshot.Mode == "serving", true
}
