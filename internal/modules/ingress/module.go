// Package ingress assembles ingress-owned adapters; only composition imports it.
package ingress

import (
	"gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/infrastructure/identifiers"
	ingresspg "gatebeam/internal/modules/ingress/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func New(p *pgxpool.Pool, a application.Authorizer) *application.Service {
	return application.New(postgres.NewRunner(p), ingresspg.New(), a, audit.New(), identifiers.Generator{})
}
