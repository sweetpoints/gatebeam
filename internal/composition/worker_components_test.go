package composition

import (
	"context"
	"gatebeam/internal/platform/lifecycle"
	"testing"
	"time"
)

func TestWorkerFailuresDoNotPretendReadyOrStopIndependentClaims(t *testing.T) {
	components := newWorkerComponents()
	if components.readyError() == nil {
		t.Fatal("uninitialized components reported ready")
	}
	state := lifecycle.New(time.Now)
	ctx := lifecycle.WithState(context.Background(), state)
	ctx = withWorkerComponent(ctx, components, "")
	for _, name := range workerComponentNames {
		workerComponentReady(withWorkerComponent(ctx, components, name), true)
	}
	if e := components.readyError(); e != nil {
		t.Fatal(e)
	}
	workerComponentReady(withWorkerComponent(ctx, components, "archive"), false)
	state.SetReady(lifecycle.GlobalJobs, false)
	if components.readyError() == nil {
		t.Fatal("failed component reported healthy")
	}
	if !roleAccepts(ctx, lifecycle.GlobalJobs) {
		t.Fatal("archive outage stopped independent local query claims")
	}
	state.SetMaintenance(true)
	if roleAccepts(ctx, lifecycle.GlobalJobs) {
		t.Fatal("maintenance allowed new claims")
	}
}
