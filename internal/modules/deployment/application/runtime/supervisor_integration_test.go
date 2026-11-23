package runtime_test

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"testing"
	"testing/synctest"
	"time"
)

type memoryDisk struct {
	j       domain.ApplyJournal
	current string
}

func (d *memoryDisk) Lock(context.Context) (func(), error)                     { return func() {}, nil }
func (d *memoryDisk) Stage(_ context.Context, a edge.Artifact) (string, error) { return a.ID, nil }
func (d *memoryDisk) Switch(_ context.Context, id string) error                { d.current = id; return nil }
func (d *memoryDisk) Load(context.Context) (domain.ApplyJournal, error)        { return d.j, nil }
func (d *memoryDisk) Save(_ context.Context, j domain.ApplyJournal) error      { d.j = j; return nil }

type nativePort struct {
	invalid, down bool
	version       string
	disk          *memoryDisk
}

func (p *nativePort) Validate(context.Context, string) error {
	if p.invalid {
		return errors.New("invalid Nginx config")
	}
	return nil
}
func (p *nativePort) Activate(context.Context, string) error  { p.version = p.disk.current; return nil }
func (p *nativePort) Observe(context.Context) (string, error) { return p.version, nil }
func (p *nativePort) RotateLogs(context.Context) error        { return nil }
func (p *nativePort) Stop(context.Context) error              { return nil }

type compiler struct{}

func (compiler) Compile(s app.Snapshot, r edge.RuntimeState) (edge.Artifact, error) {
	return edge.Artifact{ID: s.Version + "/" + r.Generation}, nil
}

type authority struct {
	down      bool
	old, new  edge.Plan
	confirmed bool
}

func (a *authority) Prepare(context.Context, string) (edge.Plan, error) {
	if a.down {
		return edge.Plan{}, errors.New("database unavailable")
	}
	return a.new, nil
}
func (a *authority) Within(_ context.Context, _ string, _ edge.Plan, fn func() error) error {
	if a.down {
		return errors.New("database unavailable")
	}
	return fn()
}
func (a *authority) CurrentVerified(context.Context) (edge.Plan, error) {
	if a.down {
		return edge.Plan{}, errors.New("database unavailable")
	}
	return a.old, nil
}
func (a *authority) Confirmed(context.Context, domain.ApplyJournal) (bool, error) {
	if a.down {
		return false, errors.New("database unavailable")
	}
	return a.confirmed, nil
}
func harness() (*edge.Supervisor, *memoryDisk, *nativePort, *authority) {
	d := &memoryDisk{current: "old/g1"}
	p := &nativePort{version: "old/g1", disk: d}
	a := &authority{old: edge.Plan{Snapshot: app.Snapshot{Version: "old"}, Runtime: edge.RuntimeState{Generation: "g1"}}, new: edge.Plan{Snapshot: app.Snapshot{Version: "new"}, Runtime: edge.RuntimeState{Generation: "g2"}}}
	return edge.NewSupervisor(p, d, d, compiler{}, a), d, p, a
}
func TestValidationFailureKeepsOldConfig(t *testing.T) {
	s, d, p, _ := harness()
	p.invalid = true
	r, e := s.Apply(context.Background(), "new")
	if e == nil || r.State != "failed" || d.current != "old/g1" || p.version != "old/g1" {
		t.Fatalf("old configuration changed: %+v %v", r, e)
	}
}
func TestCrashAfterSwitchReconciles(t *testing.T) {
	s, d, p, _ := harness()
	d.current = "new/g2"
	p.version = "new/g2"
	d.j = domain.ApplyJournal{CandidateID: "new", ArtifactID: "new/g2", Version: "new/g2", PreviousVersion: "old/g1", State: domain.Verifying, ReceiptPending: true}
	r, e := s.Recover(context.Background())
	if e != nil || r.State != "restored" || p.version != "old/g1" {
		t.Fatalf("actual uncommitted version not recovered: %+v %v", r, e)
	}
}
func TestLostDatabaseDoesNotExitNginx(t *testing.T) {
	s, _, p, a := harness()
	a.down = true
	_, e := s.Apply(context.Background(), "new")
	if e == nil || p.version != "old/g1" {
		t.Fatalf("DB loss changed Nginx: %s %v", p.version, e)
	}
}

func (a *authority) WithRestore(ctx context.Context, _ edge.Plan, fn func(context.Context) error) error {
	if a.down {
		return errors.New("database unavailable")
	}
	return fn(ctx)
}

// Authority acquisition can consume its entire final-effect budget. It must
// pass that exact context to the effect, rather than letting the longer outer
// recovery/derived context authorize a switch after the budget is gone.
type cancelledRestoreAuthority struct {
	*authority
	final context.Context
}

func (a *cancelledRestoreAuthority) WithRestore(ctx context.Context, _ edge.Plan, fn func(context.Context) error) error {
	final, cancel := context.WithCancel(ctx)
	a.final = final
	cancel()
	return fn(final)
}

type effectDisk struct {
	*memoryDisk
	switches int
}

func (d *effectDisk) Switch(ctx context.Context, id string) error {
	d.switches++
	return d.memoryDisk.Switch(ctx, id)
}
func TestRestoreCancelledAuthorityCannotSwitch(t *testing.T) {
	for _, mode := range []string{"recover", "derived"} {
		t.Run(mode, func(t *testing.T) {
			_, disk, process, base := harness()
			disk.current = "new/g2"
			process.version = "new/g2"
			authority := &cancelledRestoreAuthority{authority: base}
			effects := &effectDisk{memoryDisk: disk}
			supervisor := edge.NewSupervisor(process, effects, disk, compiler{}, authority)
			var err error
			if mode == "recover" {
				_, err = supervisor.Recover(context.Background())
			} else {
				_, err = supervisor.ApplyDerived(context.Background(), "certificate")
			}
			if !errors.Is(err, context.Canceled) || effects.switches != 0 || process.version != "new/g2" {
				t.Fatalf("cancelled authority reached native effect: switches=%d version=%s error=%v", effects.switches, process.version, err)
			}
		})
	}
}

type spentRestoreAuthority struct {
	*authority
	final context.Context
}

func (a *spentRestoreAuthority) WithRestore(ctx context.Context, _ edge.Plan, fn func(context.Context) error) error {
	final, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	a.final = final
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-final.Done():
		return final.Err()
	}
	return fn(final)
}

type budgetProcess struct {
	*nativePort
	authority *spentRestoreAuthority
	activated bool
}

func (p *budgetProcess) Activate(ctx context.Context, _ string) error {
	p.activated = true
	if ctx != p.authority.final {
		return errors.New("native effect received outer context")
	}
	<-ctx.Done()
	return ctx.Err()
}
func TestRestoreAuthoritySpentBudgetCancelsNativeEffect(t *testing.T) {
	// This in-memory test checks context identity and remaining time, not host
	// scheduling latency while other packages are compiling.
	synctest.Test(t, func(t *testing.T) {
		_, disk, process, base := harness()
		authority := &spentRestoreAuthority{authority: base}
		native := &budgetProcess{nativePort: process, authority: authority}
		supervisor := edge.NewSupervisor(native, disk, disk, compiler{}, authority)
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := supervisor.ApplyDerived(ctx, "certificate")
		if !native.activated || !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			t.Fatalf("native work did not use exact remaining authority budget: activated=%v outer=%v error=%v", native.activated, ctx.Err(), err)
		}
		if elapsed := time.Since(started); elapsed != 30*time.Millisecond {
			t.Fatalf("native effect extended authority deadline: elapsed=%s", elapsed)
		}
	})
}

func (a *authority) ActivateWithin(ctx context.Context, id string, p edge.Plan, fn func() error) error {
	return a.Within(ctx, id, p, fn)
}

func (a *authority) RestoreActivateWithin(ctx context.Context, p edge.Plan, fn func(context.Context) error) error {
	return a.WithRestore(ctx, p, fn)
}
func (a *cancelledRestoreAuthority) RestoreActivateWithin(ctx context.Context, p edge.Plan, fn func(context.Context) error) error {
	return a.WithRestore(ctx, p, fn)
}
func (a *spentRestoreAuthority) RestoreActivateWithin(ctx context.Context, p edge.Plan, fn func(context.Context) error) error {
	return a.WithRestore(ctx, p, fn)
}
