package upgrade

import (
	"fmt"
	"gatebeam/internal/modules/deployment/domain"
)

// Compensation is defined only for failed post-update verification, before any
// upstream/member was restored. Unknown writes never enter this path.
func Compensation(p Plan, nodeID string) ([]Step, error) {
	if p.Scope == "host" || p.Scope == "retire" {
		return nil, ErrInvalid
	}
	nodes := make([]domain.NodeDeployment, len(p.Inventory.Nodes))
	index := -1
	for j, n := range p.Inventory.Nodes {
		nodes[j] = n
		nodes[j].Roles = map[string]domain.RoleDeployment{}
		for role, r := range n.Roles {
			nodes[j].Roles[role] = r
		}
		if n.Node.ID == nodeID {
			index = j
		}
	}
	if index < 0 || p.Request.Target != nil && nodes[index].Node != *p.Request.Target {
		return nil, ErrInvalid
	}
	old := map[string]string{}
	for role, image := range p.Request.Images {
		prior := nodes[index].Roles[role]
		if prior.Image != image {
			old[role] = prior.Image
		}
	}
	if len(old) == 0 {
		return nil, ErrInvalid
	}
	for j := 0; j <= index; j++ {
		if p.Request.Target != nil && nodes[j].Node != *p.Request.Target {
			continue
		}
		for role, image := range p.Request.Images {
			r := nodes[j].Roles[role]
			r.Image = image
			nodes[j].Roles[role] = r
		}
	}
	n := nodes[index]
	steps := []Step{}
	add := func(kind string, images map[string]string, seconds int) {
		steps = append(steps, Step{Capacity: p.Inventory.Capacity, ID: fmt.Sprintf("%s-%03d", p.ID, 500+index*100+len(steps)), Kind: kind, Node: n.Node, Targets: nodes, Images: images, Seconds: seconds})
	}
	add("recovery-check", old, 0)
	add("approve-images", old, 0)
	add("update", old, 0)
	add("verify-api", old, 0)
	add("management-restore", nil, 0)
	add("verify-private", old, 0)
	add("private-add", nil, 0)
	add("verify-public", old, 0)
	add("public-add", nil, 0)
	observe := p.Request.ObserveSeconds
	if observe == 0 {
		observe = 120
	}
	add("observe", old, observe)
	return steps, nil
}

// DrainRestoration reverses only acknowledged exclusions before a role or host
// starts draining. The target keeps its original images throughout.
func DrainRestoration(p Plan, blockedID string) ([]Step, error) {
	for index, blocked := range p.Steps {
		if blocked.ID != blockedID {
			continue
		}
		var public, private bool
		switch blocked.Kind {
		case "public-remove":
		case "private-remove":
			public = true
		case "drain":
			public, private = true, true
		default:
			return nil, ErrInvalid
		}
		kinds := []string{"verify-api", "management-restore"}
		if private {
			kinds = append(kinds, "verify-private", "private-add")
		}
		if public {
			kinds = append(kinds, "verify-public", "public-add")
		}
		kinds = append(kinds, "observe")
		steps := make([]Step, 0, len(kinds))
		for i, kind := range kinds {
			steps = append(steps, Step{
				ID: fmt.Sprintf("%s-%04d", p.ID, 4000+index*10+i), Kind: kind,
				Node: blocked.Node, Targets: blocked.Targets,
			})
		}
		steps[len(steps)-1].Seconds = p.Request.ObserveSeconds
		if steps[len(steps)-1].Seconds == 0 {
			steps[len(steps)-1].Seconds = 120
		}
		return steps, nil
	}
	return nil, ErrInvalid
}
