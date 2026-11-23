package domain

import (
	"math"
	"regexp"
)

// NodeRef identifies an enrolled node incarnation, independently of its IP.
type NodeRef struct {
	ID    string `json:"id"`
	Epoch uint64 `json:"epoch"`
}

var nodeID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (n NodeRef) Valid() bool {
	return nodeID.MatchString(n.ID) && n.ID != "00000000-0000-0000-0000-000000000000" && n.Epoch > 0 && n.Epoch <= math.MaxInt64
}
