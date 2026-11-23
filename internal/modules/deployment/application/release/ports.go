package release

import (
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
)

type IDs interface{ NewID() (string, error) }
type Repository interface {
	Save(transaction.Scope, Candidate) error
	Read(transaction.Scope, string) (Candidate, error)
	Queue(transaction.Scope, string) (string, bool, error)
	List(transaction.Scope, int, int) ([]Candidate, error)
	Digest([]byte) string
}
type Candidate struct {
	ObservedVersion string `json:"observed_version"`
	RestoredVersion string `json:"restored_version"`
	Effective       bool   `json:"effective"`

	// PublishedBase is independent from chosen content: selected drafts/historical
	// versions can replace a published body without erasing this concurrency guard.
	PublishedBase   map[string]int64 `json:"published_base"`
	ID              string           `json:"id"`
	Snapshot        app.Snapshot     `json:"snapshot"`
	AffectedSiteIDs []string         `json:"affected_site_ids"`
	SelectedSiteIDs []string         `json:"selected_site_ids"`
	Expected        map[string]int64 `json:"expected"`
	InputDigest     string           `json:"input_digest"`
	Changes         []Change         `json:"changes"`
	State           domain.State     `json:"state"`
}

// Change is deliberately metadata-only: no domains, upstreams, secrets or bodies.
type Change struct {
	Fields []string `json:"fields"`
	Kind   string   `json:"kind"`
	ID     string   `json:"id"`
	Before int64    `json:"before"`
	After  int64    `json:"after"`
}
type PrepareInput struct {
	PublishedBase                    map[string]int64
	Snapshot                         app.Snapshot
	AffectedSiteIDs, SelectedSiteIDs []string
	Expected                         map[string]int64
	Changes                          []Change
}

type ExecutionRepository interface {
	RecordOutcome(transaction.Scope, string, domain.State, string, string) error
	RecordVerified(transaction.Scope, string, string, string) error
	CurrentVerified(transaction.Scope) (VerifiedReceipt, error)
}
type VerifiedReceipt struct{ ReleaseID, ArtifactID, Version string }
