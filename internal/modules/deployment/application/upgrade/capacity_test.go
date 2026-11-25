package upgrade

import (
	"gatebeam/internal/modules/deployment/domain"
	"strings"
	"testing"
	"time"
)

func TestCapacityBindsBothNodesImagesAndMeasuredDemand(t *testing.T) {
	r, i := fixture()
	p, e := BuildPlan(r, i)
	if e != nil {
		t.Fatal(e)
	}
	c := &domain.CapacityEvidence{Kind: "production", RequiredPeakRPS: 100, Digest: strings.Repeat("a", 64)}
	for _, n := range i.Nodes {
		for _, candidate := range []bool{false, true} {
			images := map[string]string{}
			limits := map[string]domain.CapacityLimit{}
			for role, record := range n.Roles {
				images[role] = record.Image
				limits[role] = domain.CapacityLimit{MemoryBytes: 256 << 20, NanoCPUs: 1e9, PIDs: 64}
			}
			if candidate {
				images["management"] = r.Images["management"]
			}
			c.Trials = append(c.Trials, domain.CapacityTrial{Node: n.Node, MachineType: "projects/owned/zones/us-west1-c/machineTypes/e2-standard-4", Images: images, Limits: limits, DurationSeconds: 10, Requests: 1000, Workload: "actual production-equivalent HTTP and concurrent query"})
		}
	}
	p.Inventory.Capacity = c
	if e = ValidateCapacity(p); e != nil {
		t.Fatal(e)
	}
	c.Trials[0].Requests = 999
	if ValidateCapacity(p) == nil {
		t.Fatal("below declared peak admitted")
	}
	c.Trials[0].Requests = 1000
	c.Kind = "fixture"
	if ValidateCapacity(p) == nil {
		t.Fatal("fixture treated as production acceptance")
	}
	c.Kind = "production"
	c.Trials = c.Trials[:3]
	if ValidateCapacity(p) == nil {
		t.Fatal("missing B candidate evidence")
	}
}

func TestRemainingCapacityUsesMeasuredFleetAtEachUpgradeStep(t *testing.T) {
	request, inventory := fleetFixture(3)
	for i := range inventory.Nodes {
		inventory.Nodes[i].PeerAddress = ""
	}
	expires := time.Now().Add(time.Hour)
	evidence := &domain.CapacityEvidence{ExpiresAt: &expires, Kind: "production", RequiredPeakRPS: 100, Digest: strings.Repeat("a", 64)}
	current := make([]domain.CapacityGroupMember, 3)
	candidate := make([]domain.CapacityGroupMember, 3)
	for i, node := range inventory.Nodes {
		for _, updating := range []bool{false, true} {
			images := map[string]string{}
			limits := map[string]domain.CapacityLimit{}
			for role, spec := range node.Roles {
				images[role] = spec.Image
				limits[role] = domain.CapacityLimit{MemoryBytes: 256 << 20, NanoCPUs: 1e9, PIDs: 64}
			}
			if updating {
				images["management"] = request.Images["management"]
				candidate[i] = domain.CapacityGroupMember{Node: node.Node, Images: images}
			} else {
				current[i] = domain.CapacityGroupMember{Node: node.Node, Images: images}
			}
			evidence.Trials = append(evidence.Trials, domain.CapacityTrial{Node: node.Node, MachineType: "projects/owned/zones/us-west1-c/machineTypes/e2-standard-4", Images: images, Limits: limits, DurationSeconds: 10, Requests: 600, Workload: "measured business load"})
		}
	}
	for _, members := range [][]domain.CapacityGroupMember{{current[1], current[2]}, {candidate[0], current[2]}, {candidate[0], candidate[1]}} {
		evidence.Groups = append(evidence.Groups, domain.CapacityGroupTrial{Members: members, DurationSeconds: 10, Requests: 1000, Workload: "load measured jointly through the shared entry"})
	}
	inventory.Capacity = evidence
	plan, err := BuildPlan(request, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCapacity(plan); err != nil {
		t.Fatalf("measured survivors should qualify: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	plan.Inventory.Capacity.ExpiresAt = &past
	if err := ValidateCapacity(plan); err == nil {
		t.Fatal("expired measurements qualified a new drain")
	}
	if err := ValidateRecoveryCapacity(plan); err != nil {
		t.Fatalf("expiry prevented recovery of an operation already in flight: %v", err)
	}
	plan.Inventory.Capacity.ExpiresAt = &expires
	plan.Inventory.Capacity.Groups[1].Members[0] = current[0]
	if err := ValidateCapacity(plan); err == nil {
		t.Fatal("a measurement taken before the first node was upgraded qualified the second drain")
	}
}
