package upgrade

import (
	"fmt"
	"gatebeam/internal/modules/deployment/domain"
)

// Compensation is defined only for failed post-update verification, before any
// upstream/member was restored. Unknown writes never enter this path.
func Compensation(p Plan, nodeID string) ([]Step, error) {
	if p.Scope == "host" {
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
	if index < 0 {
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
