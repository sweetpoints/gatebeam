package upgrade

import (
	"context"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
)

var ErrCapacity = errors.New("production single-node peak capacity qualification required for current and candidate artifacts")
var ErrInvalid = errors.New("invalid upgrade intent or inventory")
var ErrPaused = errors.New("upgrade paused; verified fencing and in-flight results required")
var ErrFailed = errors.New("new version failed read-only verification")
var ErrRolledBack = errors.New("new version rejected; previous approved image restored and verified; batch stopped")
var ErrConflict = errors.New("upgrade ownership or revision conflict")

type Step = domain.UpgradeStep
type Plan = domain.UpgradePlan
type NodeState struct {
	Ready, ControlReady    bool
	Images                 map[string]string
	ArtifactID, Generation string
}
type OperationRef struct {
	StepID         string `json:"step_id"`
	CloudOperation string `json:"cloud_operation,omitempty"`
	HostCommandID  string `json:"host_command_id,omitempty"`
}
type RecoveryProof struct {
	BatchID          string         `json:"batch_id"`
	PreviousExecutor string         `json:"previous_executor"`
	Revision         uint64         `json:"revision"`
	Operations       []OperationRef `json:"operations"`
}
type Operations interface {
	Observe(context.Context, string) (NodeState, error)
	Apply(context.Context, Step) (OperationRef, error)
	Wait(context.Context, OperationRef) error
	VerifyRecovery(context.Context, RecoveryProof) error
}
type Run struct {
	RecoverySteps []Step        `json:"recovery_steps,omitempty"`
	RecoveryNode  string        `json:"recovery_node,omitempty"`
	Plan          Plan          `json:"plan"`
	Owner         string        `json:"owner"`
	Revision      uint64        `json:"revision"`
	Next          int           `json:"next"`
	State         string        `json:"state"`
	Pending       *Step         `json:"pending,omitempty"`
	Operation     *OperationRef `json:"operation,omitempty"`
}
type Store interface {
	Create(context.Context, Run) error
	Load(context.Context, string) (Run, error)
	Save(context.Context, Run, uint64) error
}
