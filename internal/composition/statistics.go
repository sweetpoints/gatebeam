package composition

import (
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/statistics"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/modules/observability"
	"gatebeam/internal/modules/observability/application/stats"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewStatistics supplies O5's API adapter with the actual owner query and live
// identity/ingress authorization, with no signer, seed store or Parquet reader.
func NewStatistics(p *pgxpool.Pool) *stats.Service {
	catalog := &ingressaccess.Catalog{}
	access := identity.NewAccess(p, catalog)
	catalog.Ingress = ingress.New(p, ingressaccess.Authorizer{Identity: access})
	return observability.NewQuery(p, statistics.Security{Access: access})
}
