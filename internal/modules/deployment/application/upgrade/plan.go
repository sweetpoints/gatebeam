package upgrade

import (
	"encoding/json"
	"fmt"
	"gatebeam/internal/modules/deployment/domain"
	"slices"
	"strings"
)

type Request = domain.UpgradeRequest
type Inventory = domain.UpgradeInventory

// BuildPlan performs no I/O. In particular it never creates a client, probes,
// invokes gcloud (which writes credential caches), opens a DB, or acquires locks.
func BuildPlan(r Request, i Inventory) (Plan, error) {
	var snapshot struct {
		Request   Request
		Inventory Inventory
	}
	raw, e := json.Marshal(struct {
		Request   Request
		Inventory Inventory
	}{r, i})
	if e != nil || json.Unmarshal(raw, &snapshot) != nil {
		return Plan{}, ErrInvalid
	}
	r, i = snapshot.Request, snapshot.Inventory
	p := Plan{Request: r, Inventory: i, ID: r.BatchID, ExecutorInstance: r.ExecutorInstance, Scope: r.Scope}
	if !(domain.NodeRef{ID: r.BatchID, Epoch: 1}).Valid() || len(i.Nodes) != 2 || i.Schema != 27 || i.RoleSchema != 6 || !i.Compatible || !slices.Contains([]string{"node", "role", "host"}, r.Scope) {
		return p, ErrInvalid
	}
	executor := strings.Split(r.ExecutorInstance, "/")
	if len(executor) != 6 || executor[0] != "projects" || executor[2] != "zones" || executor[4] != "instances" || !domain.ValidInstanceReference(r.ExecutorInstance) {
		return p, ErrInvalid
	}
	if r.Scope == "role" && !slices.Contains(domain.NodeRoleNames(), r.Role) || r.Scope != "role" && r.Role != "" {
		return p, ErrInvalid
	}
	a, b := i.Nodes[0], i.Nodes[1]
	if a.Validate() != nil || b.Validate() != nil || a.Node.ID == b.Node.ID || a.Instance == b.Instance || a.InstanceGroup == b.InstanceGroup || a.PrivateAddress != b.PeerAddress || b.PrivateAddress != a.PeerAddress || a.PublicBackend != b.PublicBackend || a.PrivateBackend != b.PrivateBackend || a.PublicBackend == a.PrivateBackend {
		return p, ErrInvalid
	}
	zone := ""
	for _, n := range i.Nodes {
		instance, group, pub, priv := strings.Split(n.Instance, "/"), strings.Split(n.InstanceGroup, "/"), strings.Split(n.PublicBackend, "/"), strings.Split(n.PrivateBackend, "/")
		z := strings.Join(instance[:4], "/")
		if zone != "" && zone != z {
			return p, ErrInvalid
		}
		zone = z
		split := strings.LastIndex(instance[3], "-")
		if split < 1 {
			return p, ErrInvalid
		}
		region := instance[3][:split]
		if strings.Join(group[:4], "/") != z || pub[1] != instance[1] || priv[1] != instance[1] || pub[3] != region || priv[3] != region || n.Instance == r.ExecutorInstance {
			return p, ErrInvalid
		}
	}
	if r.DrainSeconds == 0 {
		r.DrainSeconds = 60
	}
	if r.ObserveSeconds == 0 {
		r.ObserveSeconds = 120
	}
	if r.DrainSeconds < 1 || r.DrainSeconds > 300 || r.ObserveSeconds < 1 || r.ObserveSeconds > 600 {
		return p, ErrInvalid
	}
	for role, image := range r.Images {
		if !slices.Contains(domain.NodeRoleNames(), role) || r.Scope == "role" && role != r.Role {
			return p, ErrInvalid
		}
		check := a
		check.Roles = map[string]domain.RoleDeployment{}
		for k, v := range a.Roles {
			check.Roles[k] = v
		}
		v := check.Roles[role]
		v.Image = image
		check.Roles[role] = v
		if check.Validate() != nil {
			return p, ErrInvalid
		}
	}
	if r.Scope != "host" && len(r.Images) == 0 || r.Scope == "host" && len(r.Images) != 0 {
		return p, ErrInvalid
	}
	add := func(kind string, n domain.NodeDeployment, images map[string]string, seconds int) {
		p.Steps = append(p.Steps, Step{Capacity: i.Capacity, ID: fmt.Sprintf("%s-%03d", r.BatchID, len(p.Steps)), Kind: kind, Node: n.Node, Targets: []domain.NodeDeployment{a, b}, Images: images, Seconds: seconds})
	}
	add("precheck", a, r.Images, 0)
	add("compatibility", a, nil, 0)
	for _, n := range i.Nodes {
		changed := map[string]string{}
		for role, image := range r.Images {
			if n.Roles[role].Image != image {
				changed[role] = image
			}
		}
		if len(changed) == 0 && r.Scope != "host" {
			continue
		}
		add("management-remove", n, nil, 0)
		add("public-remove", n, nil, 0)
		add("private-remove", n, nil, 0)
		add("drain", n, changed, r.DrainSeconds)
		add("log-flush", n, changed, 0)
		if r.Scope == "host" {
			add("host-stop", n, nil, 0)
			add("host-start", n, nil, 0)
		} else {
			add("approve-images", n, changed, 0)
			add("update", n, changed, 0)
		}
		add("verify-api", n, changed, 0)
		add("management-restore", n, nil, 0)
		add("verify-private", n, changed, 0)
		add("private-add", n, nil, 0)
		add("verify-public", n, changed, 0)
		add("public-add", n, nil, 0)
		add("observe", n, changed, r.ObserveSeconds)
	}
	if len(p.Steps) == 2 {
		return p, ErrInvalid
	}
	return p, nil
}
