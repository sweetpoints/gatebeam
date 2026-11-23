package upgrade

import (
	"gatebeam/internal/modules/deployment/domain"
	"strings"
	"testing"
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
