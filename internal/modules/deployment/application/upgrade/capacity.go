package upgrade

import (
	"gatebeam/internal/modules/deployment/domain"
	"maps"
	"math"
	"reflect"
	"strings"
	"time"
)

// ValidateCapacity verifies the shape and exact artifact/node binding of an
// operator-supplied measured qualification. It does not invent tenant demand.
func ValidateCapacity(p Plan) error { return validateCapacity(p, true) }

// ValidateRecoveryCapacity checks already-persisted evidence without applying
// expiry to read-only reconciliation or restoration of a detached node.
func ValidateRecoveryCapacity(p Plan) error { return validateCapacity(p, false) }

func validateCapacity(p Plan, checkExpiry bool) error {
	c := p.Inventory.Capacity
	if c == nil || c.Kind != "production" || c.RequiredPeakRPS < 1 || math.IsNaN(c.RequiredPeakRPS) || math.IsInf(c.RequiredPeakRPS, 0) || len(c.Digest) != 64 || len(c.Trials) < len(p.Inventory.Nodes) || len(c.Trials) > 2*len(p.Inventory.Nodes) {
		return ErrCapacity
	}
	legacyPair := len(p.Inventory.Nodes) == 2 && p.Inventory.Nodes[0].PeerAddress != "" && p.Inventory.Nodes[1].PeerAddress != ""
	if (c.ExpiresAt == nil && (!legacyPair || len(c.Groups) > 0)) ||
		(checkExpiry && c.ExpiresAt != nil && !time.Now().Before(*c.ExpiresAt)) {
		return ErrCapacity
	}
	for _, ch := range c.Digest {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return ErrCapacity
		}
	}
	for _, trial := range c.Trials {
		if !trial.Node.Valid() || !validMeasurement(trial.DurationSeconds, trial.Requests, trial.Errors, trial.P95Millis, trial.Workload) ||
			(len(c.Groups) == 0 && rate(trial.Requests, trial.DurationSeconds) < c.RequiredPeakRPS) || len(trial.Limits) != len(domain.NodeRoleNames()) {
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
	current := make(map[domain.NodeRef]map[string]string, len(p.Inventory.Nodes))
	candidates := make(map[domain.NodeRef]map[string]string, len(p.Inventory.Nodes))
	for _, n := range p.Inventory.Nodes {
		images := make(map[string]string, len(n.Roles))
		for role, r := range n.Roles {
			images[role] = r.Image
		}
		next := maps.Clone(images)
		if p.Request.Target == nil || n.Node == *p.Request.Target {
			maps.Copy(next, p.Request.Images)
		}
		if !hasTrial(c, n.Node, images) || !hasTrial(c, n.Node, next) {
			return ErrCapacity
		}
		current[n.Node], candidates[n.Node] = images, next
	}
	if len(c.Groups) > len(p.Inventory.Nodes) {
		return ErrCapacity
	}
	for _, group := range c.Groups {
		if len(group.Members) < 2 || len(group.Members) >= len(current) ||
			!validMeasurement(group.DurationSeconds, group.Requests, group.Errors, group.P95Millis, group.Workload) ||
			rate(group.Requests, group.DurationSeconds) < c.RequiredPeakRPS {
			return ErrCapacity
		}
		seen := map[domain.NodeRef]bool{}
		for _, member := range group.Members {
			if seen[member.Node] || !hasTrial(c, member.Node, member.Images) {
				return ErrCapacity
			}
			seen[member.Node] = true
		}
	}
	for _, step := range p.Steps {
		if step.Kind != "management-remove" {
			continue
		}
		delete(current, step.Node)
		if !qualifiesRemainingCapacity(c, current) {
			return ErrCapacity
		}
		current[step.Node] = candidates[step.Node]
	}
	return nil
}

func hasTrial(evidence *domain.CapacityEvidence, node domain.NodeRef, images map[string]string) bool {
	for _, trial := range evidence.Trials {
		if trial.Node == node && reflect.DeepEqual(trial.Images, images) {
			return true
		}
	}
	return false
}

func validMeasurement(duration, requests, failures int64, p95 float64, workload string) bool {
	return duration >= 10 && duration <= 86400 && requests > 0 && failures == 0 &&
		p95 >= 0 && !math.IsNaN(p95) && !math.IsInf(p95, 0) && workload != "" && len(workload) <= 2048
}

func rate(requests, duration int64) float64 { return float64(requests) / float64(duration) }

// QualifiesRemainingCapacity uses known healthy survivors and their observed
// images. A joint measurement must describe exactly that set of survivors.
func QualifiesRemainingCapacity(evidence *domain.CapacityEvidence, survivors map[domain.NodeRef]map[string]string) bool {
	if evidence == nil || evidence.ExpiresAt != nil && !time.Now().Before(*evidence.ExpiresAt) {
		return false
	}
	return qualifiesRemainingCapacity(evidence, survivors)
}

func qualifiesRemainingCapacity(evidence *domain.CapacityEvidence, survivors map[domain.NodeRef]map[string]string) bool {
	if len(survivors) == 0 {
		return false
	}
	for _, trial := range evidence.Trials {
		images, present := survivors[trial.Node]
		if present && reflect.DeepEqual(trial.Images, images) && rate(trial.Requests, trial.DurationSeconds) >= evidence.RequiredPeakRPS {
			return true
		}
	}
	for _, group := range evidence.Groups {
		if len(group.Members) != len(survivors) || rate(group.Requests, group.DurationSeconds) < evidence.RequiredPeakRPS {
			continue
		}
		matched := true
		for _, member := range group.Members {
			if images, present := survivors[member.Node]; !present || !reflect.DeepEqual(member.Images, images) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
