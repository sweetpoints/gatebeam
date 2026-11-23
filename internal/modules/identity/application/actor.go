// Package application exports the identity application contract.
package application

import "gatebeam/internal/modules/identity/domain"

type Role = domain.Role
type Action = domain.Action

const (
	Readonly  = domain.Readonly
	Editor    = domain.Editor
	Publisher = domain.Publisher
	Admin     = domain.Admin
	View      = domain.View
	Edit      = domain.Edit
	Publish   = domain.Publish
	Manage    = domain.Manage
)

type CredentialKind string

const (
	SessionCredential CredentialKind = "session"
	TokenCredential   CredentialKind = "token"
)

type Actor struct {
	UserID         string         `json:"user_id"`
	AuthVersion    int64          `json:"auth_version"`
	CredentialKind CredentialKind `json:"credential_kind"`
	CredentialID   string         `json:"credential_id"`
	Role           Role           `json:"role"`
}
