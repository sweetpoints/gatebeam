package upgrade

import (
	"gatebeam/internal/modules/deployment/domain"
	"math"
	"reflect"
	"strings"
)

// ValidateCapacity verifies the shape and exact artifact/node binding of an
// operator-supplied measured qualification. It does not invent tenant demand.
func ValidateCapacity(p Plan) error {
	c := p.Inventory.Capacity
	if c == nil || c.Kind != "production" || c.RequiredPeakRPS < 1 || math.IsNaN(c.RequiredPeakRPS) || math.IsInf(c.RequiredPeakRPS, 0) || len(c.Digest) != 64 || len(c.Trials) < 2 || len(c.Trials) > 4 {
		return ErrCapacity
	}
	for _, ch := range c.Digest {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return ErrCapacity
		}
	}
	for _, trial := range c.Trials {
		if !trial.Node.Valid() || trial.DurationSeconds < 10 || trial.DurationSeconds > 86400 || trial.Requests < 1 || trial.Errors != 0 || float64(trial.Requests)/float64(trial.DurationSeconds) < c.RequiredPeakRPS || trial.P95Millis < 0 || math.IsNaN(trial.P95Millis) || math.IsInf(trial.P95Millis, 0) || trial.Workload == "" || len(trial.Workload) > 2048 || len(trial.Limits) != 5 {
			return ErrCapacity
		}
		known := false
		for _, n := range p.Inventory.Nodes {
			if n.Node == trial.Node {
				known = true
				prefix := strings.Split(n.Instance, "/instances/")[0] + "/machineTypes/"
				if !strings.HasPrefix(trial.MachineType, prefix) || len(strings.TrimPrefix(trial.MachineType, prefix)) == 0 || strings.Contains(strings.TrimPrefix(trial.MachineType, prefix), "/") {
					return ErrCapacity
				}
			}
		}
		if !known {
			return ErrCapacity
		}
		for _, role := range domain.NodeRoleNames() {
			v, ok := trial.Limits[role]
			if !ok || v.MemoryBytes < 1 || v.NanoCPUs < 1 || v.PIDs < 1 {
				return ErrCapacity
			}
		}
	}
	for _, n := range p.Inventory.Nodes {
		current, next := map[string]string{}, map[string]string{}
		for role, r := range n.Roles {
			current[role] = r.Image
			next[role] = r.Image
		}
		for role, image := range p.Request.Images {
			next[role] = image
		}
		for _, images := range []map[string]string{current, next} {
			found := false
			for _, trial := range c.Trials {
				if trial.Node == n.Node && reflect.DeepEqual(images, trial.Images) {
					found = true
				}
			}
			if !found {
				return ErrCapacity
			}
		}
	}
	return nil
}
