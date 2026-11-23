package composition

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentDryRunReadsOnlyExplicitInputs(t *testing.T) {
	dir := t.TempDir()
	var nodes []domain.NodeDeployment
	for _, label := range []string{"a", "b"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "deploy", "nodes", label+".example.json"))
		if e != nil {
			t.Fatal(e)
		}
		var n domain.NodeDeployment
		if json.Unmarshal(raw, &n) != nil {
			t.Fatal("example")
		}
		n.Instance = strings.ReplaceAll(n.Instance, "REPLACE", "owned")
		n.InstanceGroup = strings.ReplaceAll(n.InstanceGroup, "REPLACE", "owned")
		n.PublicBackend = strings.ReplaceAll(n.PublicBackend, "REPLACE", "owned")
		n.PrivateBackend = strings.ReplaceAll(n.PrivateBackend, "REPLACE", "owned")
		for role, r := range n.Roles {
			r.Image = "registry.test/" + role + "@sha256:" + strings.Repeat("a", 64)
			n.Roles[role] = r
		}
		nodes = append(nodes, n)
	}
	intent := DeploymentIntent{Request: upgrade.Request{BatchID: "33333333-3333-4333-8333-333333333333", ExecutorInstance: "projects/owned/zones/us-west1-c/instances/operator", Scope: "role", Role: "management", Images: map[string]string{"management": "registry.test/api@sha256:" + strings.Repeat("b", 64)}}, Inventory: upgrade.Inventory{Nodes: nodes, Schema: 27, RoleSchema: 6, Compatible: true}}
	raw, e := json.Marshal(intent)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "intent.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	before, _ := os.Stat(path)
	plan, e := PlanDeployment(path)
	if e != nil || len(plan.Steps) == 0 {
		t.Fatal(e)
	}
	after, _ := os.Stat(path)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("dry run wrote local state")
	}
	if _, e = PlanDeployment(filepath.Join(dir, "missing")); e == nil {
		t.Fatal("missing explicit inventory guessed")
	}
}

func TestCloudExecutionCannotStartWithoutSingleNodePeakEvidence(t *testing.T) {
	e := ExecuteDeployment(t.Context(), upgrade.Plan{}, "/must-not-open-db-config", "projects/owned/zones/us-west1-c/instances/operator", "", upgrade.RecoveryProof{})
	if !errors.Is(e, upgrade.ErrCapacity) {
		t.Fatal("missing production peak evidence reached runtime setup", e)
	}
}

func TestCapacityDigestCannotBeReplacedAfterPlan(t *testing.T) {
	var nodes []domain.NodeDeployment
	for _, label := range []string{"a", "b"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "deploy", "nodes", label+".example.json"))
		if e != nil {
			t.Fatal(e)
		}
		var n domain.NodeDeployment
		if json.Unmarshal(raw, &n) != nil {
			t.Fatal("node")
		}
		for _, p := range []*string{&n.Instance, &n.InstanceGroup, &n.PublicBackend, &n.PrivateBackend} {
			*p = strings.ReplaceAll(*p, "REPLACE", "owned")
		}
		for role, v := range n.Roles {
			v.Image = "registry.test/" + role + "@sha256:" + strings.Repeat("a", 64)
			n.Roles[role] = v
		}
		nodes = append(nodes, n)
	}
	r := upgrade.Request{BatchID: "33333333-3333-4333-8333-333333333333", ExecutorInstance: "projects/owned/zones/us-west1-c/instances/operator", Scope: "role", Role: "management", Images: map[string]string{"management": "registry.test/api@sha256:" + strings.Repeat("b", 64)}}
	evidence := &domain.CapacityEvidence{Kind: "production", RequiredPeakRPS: 100}
	for _, n := range nodes {
		for _, candidate := range []bool{false, true} {
			images := map[string]string{}
			limits := map[string]domain.CapacityLimit{}
			for role, value := range n.Roles {
				images[role] = value.Image
				limits[role] = domain.CapacityLimit{MemoryBytes: 256 << 20, NanoCPUs: 1e9, PIDs: 64}
			}
			if candidate {
				images["management"] = r.Images["management"]
			}
			evidence.Trials = append(evidence.Trials, domain.CapacityTrial{Node: n.Node, MachineType: "projects/owned/zones/us-west1-c/machineTypes/e2-standard-4", Images: images, Limits: limits, DurationSeconds: 10, Requests: 1000, Workload: "measured production-equivalent fixture for validation only"})
		}
	}
	raw, _ := json.Marshal(evidence)
	sum := sha256.Sum256(raw)
	evidence.Digest = hex.EncodeToString(sum[:])
	p, e := upgrade.BuildPlan(r, upgrade.Inventory{Nodes: nodes, Schema: 27, RoleSchema: 6, Compatible: true, Capacity: evidence})
	if e != nil {
		t.Fatal(e)
	}
	if e = deploymentCapacity(p); e != nil {
		t.Fatal("valid canonical record rejected", e)
	}
	p.Inventory.Capacity.Trials[0].Requests++
	if deploymentCapacity(p) == nil {
		t.Fatal("capacity contents changed without matching digest")
	}
}
