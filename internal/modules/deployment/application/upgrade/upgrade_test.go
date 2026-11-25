package upgrade

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/domain"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func fixture() (Request, Inventory) { return fleetFixture(2) }

func fleetFixture(count int) (Request, Inventory) {
	nodes := []domain.NodeDeployment{}
	for i := range count {
		digit := fmt.Sprint(i + 1)
		id := strings.Repeat(digit, 8) + "-" + strings.Repeat(digit, 4) + "-4" + strings.Repeat(digit, 3) + "-8" + strings.Repeat(digit, 3) + "-" + strings.Repeat(digit, 12)
		name := fmt.Sprintf("gateway-%d", i)
		own := fmt.Sprintf("10.1.0.%d", 10+i)
		peer := fmt.Sprintf("10.1.0.%d", 11-i)
		n := domain.NodeDeployment{Node: domain.NodeRef{ID: id, Epoch: 1}, PrivateAddress: own, PeerAddress: peer, Instance: "projects/owned/zones/us-west1-c/instances/" + name, InstanceGroup: "projects/owned/zones/us-west1-c/instanceGroups/" + name, PublicBackend: "projects/owned/regions/us-west1/backendServices/public", PrivateBackend: "projects/owned/regions/us-west1/backendServices/private", ComposeFile: "/opt/gatebeam/compose.yaml", EnvironmentFile: "/etc/gatebeam/node.env", StoragePrefix: name, Roles: map[string]domain.RoleDeployment{}}
		for j, role := range domain.NodeRoleNames() {
			n.Roles[role] = domain.RoleDeployment{Image: "registry.test/" + role + "@sha256:" + strings.Repeat("a", 64), Protocol: 1, ConfigFile: "/etc/gatebeam/" + role + ".json", HealthPort: 19091 + j, ControlVolume: name + "-" + role + "-control"}
		}
		nodes = append(nodes, n)
	}
	return Request{BatchID: "33333333-3333-4333-8333-333333333333", ExecutorInstance: "projects/owned/zones/us-west1-c/instances/operator", Scope: "role", Role: "management", Images: map[string]string{"management": "registry.test/api@sha256:" + strings.Repeat("b", 64)}}, Inventory{Nodes: nodes, Schema: 27, RoleSchema: 6, Compatible: true}
}
func TestDryRunPerformsZeroWrites(t *testing.T) {
	r, i := fixture()
	before := fmt.Sprintf("%#v", i)
	p, e := BuildPlan(r, i)
	if e != nil || len(p.Steps) == 0 {
		t.Fatal(e)
	}
	if fmt.Sprintf("%#v", i) != before {
		t.Fatal("inventory mutated")
	}
	q, e := BuildPlan(r, i)
	if e != nil || !reflect.DeepEqual(p, q) {
		t.Fatal("non deterministic dry run")
	}
	i.Nodes = nil
	if _, e = BuildPlan(r, i); e == nil {
		t.Fatal("missing inventory accepted")
	}
}

func TestExplicitFleetUsesOneNodeAtATime(t *testing.T) {
	request, inventory := fleetFixture(3)
	for i := range inventory.Nodes {
		inventory.Nodes[i].PeerAddress = ""
	}
	plan, err := BuildPlan(request, inventory)
	if err != nil {
		t.Fatal(err)
	}
	var visited []domain.NodeRef
	var drained domain.NodeRef
	for _, step := range plan.Steps {
		switch step.Kind {
		case "management-remove":
			if drained.Valid() || len(step.Targets) != 3 {
				t.Fatalf("unsafe drain: %+v", step)
			}
			drained = step.Node
			visited = append(visited, step.Node)
		case "observe":
			if step.Node != drained {
				t.Fatalf("observation does not match drained node: %+v", step)
			}
			drained = domain.NodeRef{}
		}
	}
	want := []domain.NodeRef{inventory.Nodes[0].Node, inventory.Nodes[1].Node, inventory.Nodes[2].Node}
	if !slices.Equal(visited, want) || drained.Valid() {
		t.Fatalf("not a complete sequential plan: %v", visited)
	}
	inventory.Nodes = inventory.Nodes[:1]
	if _, err := BuildPlan(request, inventory); !errors.Is(err, ErrCapacity) {
		t.Fatalf("single-node deployment must be expanded before drain, got %v", err)
	}
}

type fakeOps struct {
	calls       []Step
	fail        string
	recoveryErr error
	images      map[string]string
}

func (f *fakeOps) Observe(context.Context, string) (NodeState, error) {
	return NodeState{Ready: true, ControlReady: true, Images: f.images}, nil
}
func (f *fakeOps) Apply(_ context.Context, s Step) (OperationRef, error) {
	f.calls = append(f.calls, s)
	if s.Kind == f.fail {
		return OperationRef{}, context.DeadlineExceeded
	}
	return OperationRef{StepID: s.ID, HostCommandID: s.ID}, nil
}
func (f *fakeOps) Wait(context.Context, OperationRef) error            { return nil }
func (f *fakeOps) VerifyRecovery(context.Context, RecoveryProof) error { return f.recoveryErr }
func TestUpgradeNeverTouchesSecondNodeBeforeFirstVerified(t *testing.T) {
	r, i := fixture()
	p, _ := BuildPlan(r, i)
	o := &fakeOps{fail: "verify-public"}
	s := NewMemoryStore()
	x := Executor{Store: s, Operations: o, ExecutorInstance: r.ExecutorInstance}
	if x.Run(t.Context(), p) == nil {
		t.Fatal("failure swallowed")
	}
	for _, v := range o.calls {
		if v.Node.ID == i.Nodes[1].Node.ID {
			t.Fatal("second node touched before verification")
		}
	}
	seen := map[string]int{}
	for j, v := range p.Steps {
		if _, ok := seen[v.Kind]; !ok {
			seen[v.Kind] = j
		}
	}
	if !(seen["management-remove"] < seen["public-remove"] && seen["verify-api"] < seen["management-restore"] && seen["verify-private"] < seen["private-add"] && seen["verify-public"] < seen["public-add"]) {
		t.Fatal("unsafe order", seen)
	}
}
func TestTimeoutDoesNotMeanNotExecuted(t *testing.T) {
	r, i := fixture()
	p, _ := BuildPlan(r, i)
	o := &fakeOps{fail: "update"}
	s := NewMemoryStore()
	x := Executor{Store: s, Operations: o, ExecutorInstance: r.ExecutorInstance}
	if !errors.Is(x.Run(t.Context(), p), ErrPaused) {
		t.Fatal("not paused")
	}
	count := len(o.calls)
	if x.Run(t.Context(), p) == nil || len(o.calls) != count {
		t.Fatal("unknown result blindly repeated")
	}
	run, _ := s.Load(t.Context(), p.ID)
	if run.Pending == nil || run.Pending.Kind != "update" {
		t.Fatal("intent lost")
	}
}
func TestPausedExecutorRequiresFencingProof(t *testing.T) {
	r, i := fixture()
	p, _ := BuildPlan(r, i)
	o := &fakeOps{fail: "update", recoveryErr: errors.New("old executor running")}
	s := NewMemoryStore()
	x := Executor{Store: s, Operations: o, ExecutorInstance: r.ExecutorInstance}
	_ = x.Run(t.Context(), p)
	run, _ := s.Load(t.Context(), p.ID)
	next := Executor{Store: s, Operations: o, ExecutorInstance: "projects/owned/zones/us-west1-c/instances/operator-next"}
	proof := RecoveryProof{BatchID: p.ID, PreviousExecutor: r.ExecutorInstance, Revision: run.Revision, Operations: []OperationRef{{StepID: run.Pending.ID, HostCommandID: run.Pending.ID}}}
	before := len(o.calls)
	if next.Resume(t.Context(), p.ID, proof) == nil || len(o.calls) != before {
		t.Fatal("unfenced takeover")
	}
	o.recoveryErr = nil
	o.fail = ""
	if e := next.Resume(t.Context(), p.ID, proof); e != nil {
		t.Fatal(e)
	}
	for _, c := range o.calls[before:] {
		if c.ID == run.Pending.ID {
			t.Fatal("completed uncertain step repeated")
		}
	}
}

type memoryStore struct{ runs map[string]Run }

func NewMemoryStore() *memoryStore { return &memoryStore{runs: map[string]Run{}} }
func (m *memoryStore) Create(_ context.Context, r Run) error {
	if _, ok := m.runs[r.Plan.ID]; ok {
		return ErrConflict
	}
	m.runs[r.Plan.ID] = r
	return nil
}
func (m *memoryStore) Load(_ context.Context, id string) (Run, error) {
	r, ok := m.runs[id]
	if !ok {
		return r, ErrConflict
	}
	return r, nil
}
func (m *memoryStore) Save(_ context.Context, r Run, rev uint64) error {
	old, ok := m.runs[r.Plan.ID]
	if !ok || old.Revision != rev {
		return ErrConflict
	}
	m.runs[r.Plan.ID] = r
	return nil
}

func TestExecutorRejectsReorderedDryRunAndInvalidZone(t *testing.T) {
	r, i := fixture()
	p, e := BuildPlan(r, i)
	if e != nil {
		t.Fatal(e)
	}
	p.Steps[2], p.Steps[3] = p.Steps[3], p.Steps[2]
	o := &fakeOps{}
	x := Executor{Store: NewMemoryStore(), Operations: o, ExecutorInstance: r.ExecutorInstance}
	if x.Run(t.Context(), p) == nil || len(o.calls) != 0 {
		t.Fatal("reordered dry-run executed")
	}
	i.Nodes[0].Instance = "projects/owned/zones/invalid/instances/a"
	if _, e = BuildPlan(r, i); e == nil {
		t.Fatal("invalid zone accepted")
	}
}

type badVersion struct {
	fakeOps
	failed bool
}

func (b *badVersion) Wait(_ context.Context, op OperationRef) error {
	for _, s := range b.calls {
		if s.ID == op.StepID && s.Kind == "verify-api" && !b.failed {
			b.failed = true
			return ErrFailed
		}
	}
	return nil
}
func TestBadVersionRestoresOnlyFailedNodeAndStopsBatch(t *testing.T) {
	r, i := fixture()
	p, _ := BuildPlan(r, i)
	ops := &badVersion{}
	store := NewMemoryStore()
	x := Executor{Store: store, Operations: ops, ExecutorInstance: r.ExecutorInstance}
	if !errors.Is(x.Run(t.Context(), p), ErrRolledBack) {
		t.Fatal("failed version not restored")
	}
	restored := false
	for _, s := range ops.calls {
		if s.Node.ID == i.Nodes[1].Node.ID {
			t.Fatal("B touched after failed A")
		}
		if s.Kind == "update" && s.Images["management"] == i.Nodes[0].Roles["management"].Image {
			restored = true
		}
	}
	run, _ := store.Load(t.Context(), p.ID)
	if !restored || run.State != "rolled_back" {
		t.Fatal("rollback not durably completed", run.State)
	}
}

func TestInputMutationCannotChangePersistedIntent(t *testing.T) {
	r, i := fixture()
	p, e := BuildPlan(r, i)
	if e != nil {
		t.Fatal(e)
	}
	old := p.Inventory.Nodes[0].Roles["management"]
	r.Images["management"] = "changed"
	i.Nodes[0].Roles["management"] = domain.RoleDeployment{}
	if p.Request.Images["management"] == "changed" || p.Inventory.Nodes[0].Roles["management"] != old {
		t.Fatal("caller mutated planned authority")
	}
}

func TestCapacityDropPausesBeforeDispatchingDrain(t *testing.T) {
	request, inventory := fixture()
	plan, err := BuildPlan(request, inventory)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	operations := &fakeOps{}
	executor := Executor{Store: store, Operations: operations, ExecutorInstance: request.ExecutorInstance, CheckBeforeStep: func(_ context.Context, step Step) error {
		if step.Kind == "management-remove" {
			return ErrCapacity
		}
		return nil
	}}
	if err := executor.Run(t.Context(), plan); !errors.Is(err, ErrPaused) || !errors.Is(err, ErrCapacity) {
		t.Fatalf("unsafe upgrade did not pause for capacity: %v", err)
	}
	run, err := store.Load(t.Context(), plan.ID)
	if err != nil || run.Pending != nil || run.State != "paused" {
		t.Fatalf("a read-only capacity check left an uncertain operation: %+v, %v", run, err)
	}
	for _, step := range operations.calls {
		if step.Kind == "management-remove" || step.Kind == "public-remove" || step.Kind == "private-remove" {
			t.Fatal("a drain was dispatched after capacity failed")
		}
	}
}

func TestRetirementDrainsExactlyTheSelectedNode(t *testing.T) {
	request, inventory := fleetFixture(3)
	request.Scope, request.Role, request.Images = "retire", "", nil
	request.Target = &inventory.Nodes[2].Node
	plan, err := BuildPlan(request, inventory)
	if err != nil {
		t.Fatal(err)
	}
	var effects []string
	for _, step := range plan.Steps[2:] {
		if step.Node != *request.Target {
			t.Fatalf("retirement touched another node: %+v", step)
		}
		effects = append(effects, step.Kind)
	}
	want := []string{"management-remove", "public-remove", "private-remove", "drain", "log-flush", "retire-membership"}
	if !slices.Equal(effects, want) {
		t.Fatalf("retirement effects = %v, want %v", effects, want)
	}
}

func TestCapacityLossRestoresConfirmedPartialDrain(t *testing.T) {
	request, inventory := fixture()
	plan, err := BuildPlan(request, inventory)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	images := make(map[string]string)
	for role, deployment := range inventory.Nodes[0].Roles {
		images[role] = deployment.Image
	}
	ops := &fakeOps{images: images}
	executor := Executor{Store: store, Operations: ops, ExecutorInstance: request.ExecutorInstance,
		CheckBeforeStep: func(_ context.Context, step Step) error {
			if step.Kind == "private-remove" {
				return ErrCapacity
			}
			return nil
		},
	}
	if err := executor.Run(t.Context(), plan); !errors.Is(err, ErrCapacity) || !errors.Is(err, ErrPaused) {
		t.Fatalf("capacity loss returned %v", err)
	}
	var operations []string
	for _, step := range ops.calls {
		if step.Node != inventory.Nodes[0].Node {
			t.Fatalf("another gateway was modified: %+v", step)
		}
		operations = append(operations, step.Kind)
	}
	want := []string{"precheck", "compatibility", "management-remove", "public-remove",
		"verify-api", "management-restore", "verify-public", "public-add", "observe"}
	if !slices.Equal(operations, want) {
		t.Fatalf("got %v, want %v", operations, want)
	}
	batch, err := store.Load(t.Context(), plan.ID)
	if err != nil || batch.State != "rolled_back" || batch.Pending != nil {
		t.Fatalf("restoration not confirmed in journal: %+v, %v", batch, err)
	}
}
