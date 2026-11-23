// Package deployment assembles only deployment-owned persistence.
package deployment

import (
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	"gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

func New() *release.Service { return release.New(postgres.New(), identifiers.Generator{}) }

func NewNodes() *nodes.Service {
	service := nodes.New(postgres.New(), time.Now)
	service.SetAudit(audit.New(), identifiers.Generator{})
	return service
}

func NewEvents(p *pgxpool.Pool) *postgres.Events { return postgres.NewEvents(jobs.New(p)) }
