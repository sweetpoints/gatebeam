package observability

import (
	"context"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
)

func CaptureLogCutoff(ctx context.Context, logs, node string) ([]domain.Segment, error) {
	source, e := logfile.OpenNode(logs, node)
	if e != nil {
		return nil, e
	}
	defer source.Close()
	return source.Discover(ctx)
}
func VerifyLogCutoff(ctx context.Context, p *pgxpool.Pool, node string, segments []domain.Segment, archived bool) (bool, error) {
	ready := false
	e := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		var e error
		ready, e = repo.NewNode(node).VerifyLogCutoff(sc, segments, archived)
		return e
	})
	return ready, e
}
