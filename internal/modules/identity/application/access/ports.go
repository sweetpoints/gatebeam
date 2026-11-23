// Package access owns current-state identity authorization.
package access

import (
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Repository interface {
	Lock(transaction.Scope) error
	ReadLock(transaction.Scope) error
	CurrentAccount(transaction.Scope, string) (domain.Account, error)
	SessionByID(transaction.Scope, string) (domain.Session, error)
	TokenByID(transaction.Scope, string) (domain.APIToken, error)
	TokenByDigest(transaction.Scope, string) (domain.APIToken, error)
	CreateToken(transaction.Scope, domain.APIToken) error
	RevokeToken(transaction.Scope, string) error
	Grants(transaction.Scope, string) ([]domain.Grant, error)
	ReplaceGrants(transaction.Scope, string, []domain.Grant) error
	ChangeRole(transaction.Scope, string, domain.Role) error
	ListAccounts(transaction.Scope, int32, int32) ([]AccountView, error)
	ListTokens(transaction.Scope, string, int32, int32) ([]TokenView, error)
	ListAudit(transaction.Scope, int32, int32) ([]AuditView, error)
}

// Catalog belongs to this consumer. The ingress adapter must freeze its membership
// snapshot under the ingress watermark after the identity watermark is acquired.
type Catalog interface {
	SiteGroupsWithin(transaction.Scope, string) ([]string, error)
}
type DenyCatalog struct{}

func (DenyCatalog) SiteGroupsWithin(transaction.Scope, string) ([]string, error) {
	return nil, domain.ErrDenied
}

type Credentials interface {
	NewID() (string, error)
	Random() (string, error)
	Digest(string) string
}
type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type AccountView struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	State       string      `json:"state"`
	Role        domain.Role `json:"role"`
	AuthVersion int64       `json:"auth_version"`
}
type TokenView struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Actions   []string  `json:"actions"`
	SiteIDs   []string  `json:"site_ids"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked"`
}
type AuditView struct {
	ID         string    `json:"id"`
	ActorID    string    `json:"actor_id"`
	Action     string    `json:"action"`
	OccurredAt time.Time `json:"occurred_at"`
}

// GroupCatalog is the narrow existence contract required for editor creation.
// Membership and existence remain ingress-owned and frozen under its watermark.
type GroupCatalog interface {
	GroupExistsWithin(transaction.Scope, string) error
}
