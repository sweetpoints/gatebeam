package composition

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	"gatebeam/internal/modules/deployment/domain"
	"time"
)

type workerRuntime interface {
	Snapshot(context.Context) (app.Snapshot, error)
	Flush(context.Context) error
}
type workerHealth interface {
	Check(context.Context, string, int64) (health.Transition, error)
}
type workerLoop struct {
	runtime     workerRuntime
	health      workerHealth
	diagnostics *workerDiagnostics
	now         func() time.Time
	due         map[string]time.Time
	cursor      int
}

func newWorkerLoop(r workerRuntime, h workerHealth, d *workerDiagnostics, now func() time.Time) *workerLoop {
	return &workerLoop{runtime: r, health: h, diagnostics: d, now: now, due: map[string]time.Time{}}
}
func (w *workerLoop) step(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	step, done := context.WithTimeout(ctx, domain.MaxHealthBudget)
	defer done()
	snapshot, err := w.runtime.Snapshot(step)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		w.diagnostics.failure(workerSnapshot, err, w.now())
	} else if len(snapshot.Targets) > 0 {
		// One bounded check per tick, with the existing rotating cursor and due
		// times. Errors remain retryable and cannot terminate the producer process.
		for n := 0; n < len(snapshot.Targets); n++ {
			i := (w.cursor + n) % len(snapshot.Targets)
			target := snapshot.Targets[i]
			key := target.ID + "/" + snapshot.Version
			if w.now().Before(w.due[key]) {
				continue
			}
			_, err = w.health.Check(step, target.ID, target.Revision)
			if ctx.Err() != nil {
				return
			}
			w.diagnostics.failure(workerCheck, err, w.now())
			w.due[key] = w.now().Add(health.Policy(target.Config.Health).Interval)
			w.cursor = (i + 1) % len(snapshot.Targets)
			break
		}
		if len(w.due) > 2*len(snapshot.Targets) {
			keep := map[string]time.Time{}
			for _, target := range snapshot.Targets {
				key := target.ID + "/" + snapshot.Version
				keep[key] = w.due[key]
			}
			w.due = keep
		}
	}
	err = w.runtime.Flush(step)
	if ctx.Err() != nil {
		return
	}
	w.diagnostics.failure(workerFlush, err, w.now())
}
