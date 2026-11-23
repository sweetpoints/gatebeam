// Package identity assembles only identity adapters for the API process.
package identity

import (
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/application/auth"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	"gatebeam/internal/modules/identity/infrastructure/otp"
	"gatebeam/internal/modules/identity/infrastructure/password"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

func New(p *pgxpool.Pool, se *secrets.Store) *auth.Service {
	s, _ := NewWithCatalog(p, se, access.DenyCatalog{})
	return s
}

// NewWithCatalog wires current ingress membership into live identity authority.
func NewWithCatalog(p *pgxpool.Pool, se *secrets.Store, cat access.Catalog) (*auth.Service, *access.Service) {
	s := auth.New(postgres.NewRunner(p), repo.New(), audit.New(), password.New(), otp.New(), se, time.Now, credential.New())
	a := access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), cat, time.Now)
	s.SetAccess(a)
	return s, a
}

// NewAccess assembles current credential/ACL verification without opening the
// authentication seed store. Edge receives no identity encryption secret.
func NewAccess(p *pgxpool.Pool, cat access.Catalog) *access.Service {
	return access.New(postgres.NewRunner(p), repo.New(), audit.New(), credential.New(), cat, time.Now)
}
