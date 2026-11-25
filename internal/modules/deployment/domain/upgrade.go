package domain

// UpgradeStep is a closed operator action with immutable inventory and image
// intent. IDs are assigned by the pure planner before external effects.
type UpgradeStep struct {
	Capacity *CapacityEvidence `json:"capacity,omitempty"`
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Node     NodeRef           `json:"node"`
	Targets  []NodeDeployment  `json:"targets"`
	Images   map[string]string `json:"images,omitempty"`
	Seconds  int               `json:"seconds,omitempty"`
}
type UpgradePlan struct {
	Request          UpgradeRequest   `json:"request"`
	Inventory        UpgradeInventory `json:"inventory"`
	ID               string           `json:"id"`
	ExecutorInstance string           `json:"executor_instance"`
	Scope            string           `json:"scope"`
	Steps            []UpgradeStep    `json:"steps"`
}

type UpgradeRequest struct {
	BatchID          string            `json:"batch_id"`
	ExecutorInstance string            `json:"executor_instance"`
	Scope            string            `json:"scope"`
	Role             string            `json:"role,omitempty"`
	Target           *NodeRef          `json:"target,omitempty"`
	Images           map[string]string `json:"images,omitempty"`
	DrainSeconds     int               `json:"drain_seconds,omitempty"`
	ObserveSeconds   int               `json:"observe_seconds,omitempty"`
}
type UpgradeInventory struct {
	Capacity   *CapacityEvidence `json:"capacity,omitempty"`
	Nodes      []NodeDeployment  `json:"nodes"`
	Schema     int64             `json:"schema"`
	RoleSchema int64             `json:"role_schema"`
	Compatible bool              `json:"compatible"`
}
