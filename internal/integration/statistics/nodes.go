package statistics

import (
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/platform/transaction"
)

type Nodes struct{ Registry *nodes.Service }

func (n Nodes) TargetsWithin(sc transaction.Scope) ([]query.LocalNode, error) {
	refs, e := n.Registry.TargetsWithin(sc)
	if e != nil {
		return nil, e
	}
	out := make([]query.LocalNode, 0, len(refs))
	for _, r := range refs {
		out = append(out, query.LocalNode{NodeID: r.ID, Epoch: r.Epoch})
	}
	return out, nil
}

func (n Nodes) AuthorizeLegacyMappingWithin(sc transaction.Scope, node string) error {
	return n.Registry.AuthorizeLegacyMappingWithin(sc, node)
}
