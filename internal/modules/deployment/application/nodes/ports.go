package nodes

import (
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"time"
)

type NodeRegistration struct {
	Node                        domain.NodeRef
	EncryptionRecipients        map[string]string
	Principal                   string
	RolePrincipals              map[string]string
	RuntimeProtocol, BootFormat uint32
	BootArtifactID              string
	BridgeImages                map[string]string
	RoleProtocols               map[string]uint32
	Original                    *Observation
}

type Observation struct {
	EventID     string                    `json:"event_id"`
	Node        domain.NodeRef            `json:"node"`
	ReleaseID   string                    `json:"release_id"`
	ArtifactID  string                    `json:"artifact_id"`
	Generation  string                    `json:"generation"`
	ImageDigest string                    `json:"image_digest"`
	ObservedAt  time.Time                 `json:"observed_at"`
	State       string                    `json:"state"`
	NodeState   string                    `json:"node_state,omitempty"`
	Bindings    []release.MaterialBinding `json:"-"`
}

type Summary struct {
	Expected  int           `json:"expected"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
	State     string        `json:"state"`
	Complete  bool          `json:"complete"`
	Degraded  bool          `json:"degraded"`
	Nodes     []Observation `json:"nodes"`
}

type Repository interface {
	NodeManagementPrincipal(transaction.Scope) (string, error)
	RegisterNode(transaction.Scope, NodeRegistration) (domain.NodeRef, error)
	ActivateNodes(transaction.Scope, []domain.NodeRef) error
	SetNodeStatus(transaction.Scope, domain.NodeRef, string) error
	AuthenticateNode(transaction.Scope, domain.NodeRef) error
	AuthenticateNodeImage(transaction.Scope, domain.NodeRef, string) error
	RequireDesiredNode(transaction.Scope, domain.NodeRef, string) error
	ActiveNodeTargets(transaction.Scope) ([]domain.NodeRef, error)
	SetNodeDesired(transaction.Scope, string, []domain.NodeRef) error
	ReportNode(transaction.Scope, Observation) error
	ListNodeObservations(transaction.Scope, string) ([]Observation, error)
	CurrentNodeObservation(transaction.Scope, domain.NodeRef) (Observation, error)
}

type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type IDs interface{ NewID() (string, error) }

// ActivationProbe is live private role-health evidence. The repository also
// checks the actual registered incarnation and durable native observations.
type ActivationProbe struct {
	Node                   domain.NodeRef
	ArtifactID, Generation string
	Images                 map[string]string
}
