package health

import (
	"context"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"net/netip"
	"testing"
	"time"
)

type memoryStore struct {
	work      Work
	committed bool
	next      Update
	stale     bool
}

func (s *memoryStore) Load(context.Context, string, int64) (Work, error) { return s.work, nil }
func (s *memoryStore) Commit(_ context.Context, u Update) (Transition, error) {
	s.next = u
	if s.stale {
		return Transition{Ignored: true}, nil
	}
	s.committed = true
	return Transition{Changed: true, Revision: u.Work.Target.Revision, Generation: "next"}, nil
}

type successProbe struct{}

func (successProbe) Check(context.Context, Probe) error { return nil }

type fixedResolver struct{}

func (fixedResolver) Resolve(context.Context, app.Target) (map[string][]netip.Addr, error) {
	return map[string][]netip.Addr{"10.0.0.2": {netip.MustParseAddr("10.0.0.2")}}, nil
}
func TestCheckBindsPublishedRevisionAndSample(t *testing.T) {
	s := &memoryStore{work: Work{ReleaseID: "published", Target: app.Target{ID: "g", Revision: 2, Config: app.TargetConfig{Protocol: "http", Members: []app.TargetMember{{Address: "10.0.0.2", Port: 80, Weight: 2}}, Health: app.HealthPolicy{Enabled: true}}}, Runtime: edge.RuntimeState{}, Sequence: 7}}
	svc := New(s, fixedResolver{}, successProbe{})
	out, e := svc.Check(context.Background(), "g", 2)
	if e != nil || !out.Changed || !s.committed {
		t.Fatal(out, e)
	}
	if s.next.Work.ReleaseID != "published" || s.next.Sequence != 8 || len(s.next.Results) != 1 || s.next.Results[0].Endpoint != "10.0.0.2:80" {
		t.Fatalf("unbound sample: %+v", s.next)
	}
}
func TestOldHealthResultCannotDisableNewMember(t *testing.T) {
	s := &memoryStore{work: Work{ReleaseID: "old", Target: app.Target{ID: "g", Revision: 1, Config: app.TargetConfig{Protocol: "http", Members: []app.TargetMember{{Address: "10.0.0.2", Port: 80}}, Health: app.HealthPolicy{Enabled: true}}}}, stale: true}
	out, e := New(s, fixedResolver{}, successProbe{}).Check(context.Background(), "g", 1)
	if e != nil || !out.Ignored || s.committed {
		t.Fatal(out, e)
	}
}
func TestDefaultsAreBounded(t *testing.T) {
	p := Policy(app.HealthPolicy{})
	if p.Interval != 5*time.Second || p.Timeout != 2*time.Second || p.Failures != 3 || p.Successes != 2 {
		t.Fatal(p)
	}
}

type manyResolver struct{}

func (manyResolver) Resolve(_ context.Context, t app.Target) (map[string][]netip.Addr, error) {
	out := map[string][]netip.Addr{}
	for _, m := range t.Config.Members {
		out[m.Address] = []netip.Addr{netip.MustParseAddr(m.Address)}
	}
	return out, nil
}

type gatedProbe struct {
	entered chan struct{}
	release chan struct{}
}

func (p gatedProbe) Check(ctx context.Context, _ Probe) error {
	p.entered <- struct{}{}
	select {
	case <-p.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestHealthChecksUseBoundedParallelism(t *testing.T) {
	members := []app.TargetMember{}
	for i := 2; i < 22; i++ {
		members = append(members, app.TargetMember{Address: fmt.Sprintf("10.0.0.%d", i), Port: 80, Weight: 1})
	}
	store := &memoryStore{work: Work{ReleaseID: "published", Target: app.Target{ID: "g", Revision: 1, Config: app.TargetConfig{Protocol: "http", Members: members, Health: app.HealthPolicy{Enabled: true}}}}}
	probe := gatedProbe{make(chan struct{}, 20), make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := New(store, manyResolver{}, probe).Check(ctx, "g", 1); done <- e }()
	defer close(probe.release)
	for i := 0; i < 8; i++ {
		select {
		case <-probe.entered:
		case <-time.After(200 * time.Millisecond):
			t.Fatal("group serialized a slow endpoint before independent checks")
		}
	}
	select {
	case <-probe.entered:
		t.Fatal("more than eight simultaneous network checks")
	default:
	}
	// Keep release closure owned once, and wait by canceling the outstanding
	// bounded checks. A canceled group must not commit a partial health verdict.
	cancel()
	if e := <-done; e == nil || store.committed {
		t.Fatal("canceled group committed", e)
	}
}
