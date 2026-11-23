// Package application owns scoped ingress use cases and immutable export contracts.
package application

import (
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
)

type ActorRef struct {
	UserID         string
	AuthVersion    int64
	CredentialKind string
	CredentialID   string
}
type Authorizer interface {
	GuardWithin(transaction.Scope, ActorRef) error
	RequireWithin(transaction.Scope, ActorRef, string, []string) error
	RequireGroupCreateWithin(transaction.Scope, ActorRef, []string) error
}
type Repository interface {
	ReadLock(transaction.Scope) error
	WriteLock(transaction.Scope) error
	Graph(transaction.Scope) (Graph, error)
	SiteGroups(transaction.Scope, string) ([]string, error)
	SaveSite(transaction.Scope, domain.Site, int64) error
	DeleteSite(transaction.Scope, string, int64) error
	SaveTarget(transaction.Scope, domain.TargetGroup, int64) error
	DeleteTarget(transaction.Scope, string, int64) error
	SaveGroup(transaction.Scope, domain.SiteGroup, int64) error
	DeleteGroup(transaction.Scope, string, int64) error
	CommandDigest([]byte) string
	Receipt(transaction.Scope, ReceiptKey) (Receipt, bool, error)
	SaveReceipt(transaction.Scope, ReceiptKey, Receipt) error
	ValidateSite(domain.SiteConfig) error
	ValidateTarget(domain.TargetConfig) error
}
type Graph struct {
	Sites   []domain.Site
	Targets []domain.TargetGroup
	Groups  []domain.SiteGroup
}
type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type IDs interface{ NewID() (string, error) }
type Draft struct {
	SiteID string            `json:"site_id"`
	Config domain.SiteConfig `json:"config"`
}
type Revision struct {
	ResourceID string `json:"resource_id"`
	Number     int64  `json:"number"`
}
type CreateSite struct {
	Name     string            `json:"name"`
	GroupIDs []string          `json:"group_ids"`
	Config   domain.SiteConfig `json:"config"`
}

// DTOs are fresh values, never live aggregate pointers or database handles.
type Site struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	GroupIDs          []string           `json:"group_ids"`
	Revision          int64              `json:"revision,omitempty"`
	Draft             *domain.SiteConfig `json:"draft,omitempty"`
	PublishedRevision int64              `json:"published_revision"`
	Published         *domain.SiteConfig `json:"published,omitempty"`
}
type TargetGroup domain.TargetGroup
type CertificateRef domain.MaterialRef
type TrustRef domain.MaterialRef
type RevisionExport struct {
	Version      string           `json:"version"`
	Sites        []Site           `json:"sites"`
	Targets      []TargetGroup    `json:"targets"`
	Certificates []CertificateRef `json:"certificates"`
	Trusts       []TrustRef       `json:"trusts"`
}

// ReleaseInputs deliberately contains separate draft and published heads. Only I2
// chooses versions for a complete Snapshot. Expected keys are site:<uuid> and
// target:<uuid>; only keys explicitly present select draft heads.
type ReleaseInputs struct {
	Export               RevisionExport
	AuthorizationSiteIDs []string
	SelectedSiteIDs      []string
	SelectedTargetIDs    []string
	Expected             map[string]int64
}

// Receipt stores no configuration body or credentials, only a command digest
// and public resource/revision metadata. Expiry is 24 hours in PostgreSQL.
type ReceiptKey struct{ ActorID, CredentialID, CredentialKind, Method, Path, Key string }
type Receipt struct {
	Digest string
	Result Revision
}
