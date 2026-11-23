package observability

import (
	"context"
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/modules/observability/infrastructure/queryipc"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// VerifyQueryCapability executes a real, bounded own-node Parquet query through
// the running private query process. An empty result is not a successful canary.
func VerifyQueryCapability(ctx context.Context, p *pgxpool.Pool, node, socket string, archive bool) error {
	var object domain.Object
	e := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		var e error
		object, e = repo.NewNode(node).CapabilityObject(sc, archive)
		return e
	})
	if e != nil {
		return e
	}
	source := "local"
	if archive {
		source = "archive"
	}
	rows, e := queryipc.NewClient(socket).Execute(ctx, domain.QueryFilter{Source: source, SiteIDs: []string{object.SiteID}, From: object.MinTime, To: object.MaxTime.Add(time.Second)}, []domain.Object{object})
	if e != nil {
		return e
	}
	if len(rows) == 0 {
		return domain.ErrIncomplete
	}
	for _, row := range rows {
		if row.NodeID != node {
			return domain.ErrInvalid
		}
	}
	return nil
}
