// Package observability assembles the owner log producer and statistics reader.
package observability

import (
	"context"
	"gatebeam/internal/modules/observability/application/archive"
	"gatebeam/internal/modules/observability/application/ingest"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/duckdb"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"gatebeam/internal/modules/observability/infrastructure/parquet"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/modules/observability/infrastructure/queryipc"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewQuery(p *pgxpool.Pool, s stats.Security) *stats.Service {
	return stats.New(postgres.NewRunner(p), s, repo.New())
}
func NewIngestor(p *pgxpool.Pool, logs, spool string) (*ingest.Ingestor, *logfile.Source, error) {
	source, e := logfile.Open(logs)
	if e != nil {
		return nil, nil, e
	}
	w, e := parquet.New(spool)
	if e != nil {
		source.Close()
		return nil, nil, e
	}
	return ingest.New(postgres.NewRunner(p), repo.New(), source, w), source, nil
}

// NewHistory assembles only API metadata/authorization operations.
func NewHistory(p *pgxpool.Pool, s query.Security) *query.Service {
	return query.New(postgres.NewRunner(p), s, repo.New())
}
func NewHistoryCoordinator(p *pgxpool.Pool, s query.Security, socket string) *query.Coordinator {
	return query.NewCoordinator(NewHistory(p, s), queryipc.NewClient(socket))
}
func RunQuery(ctx context.Context, socket string, c duckdb.Config) error {
	if err := duckdb.CheckOpenFileBudget(ctx); err != nil {
		return err
	}
	engine, e := duckdb.New(c)
	if e != nil {
		return e
	}
	return queryipc.Serve(ctx, socket, engine)
}

// NewNodeIngestor requires the controlled volume binding before any file may
// become this node's source. Copying A's volume to B cannot change provenance.
func NewNodeIngestor(p *pgxpool.Pool, logs, spool, nodeID string) (*ingest.Ingestor, *logfile.Source, error) {
	source, e := logfile.OpenNode(logs, nodeID)
	if e != nil {
		return nil, nil, e
	}
	writer, e := parquet.NewNode(spool, nodeID)
	if e != nil {
		source.Close()
		return nil, nil, e
	}
	return ingest.New(postgres.NewRunner(p), repo.NewNode(nodeID), source, writer), source, nil
}

func NewNodeHistoryCoordinator(p *pgxpool.Pool, s query.Security, socket, node string, epoch uint64) *query.Coordinator {
	return query.NewCoordinator(query.New(postgres.NewRunner(p), s, repo.NewNodeScope(node, epoch)), queryipc.NewClient(socket))
}

func MapLegacyArchives(ctx context.Context, p *pgxpool.Pool, node string, proof map[string]string, authority archive.LegacyAuthority) error {
	return postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		if authority == nil {
			return domain.ErrDenied
		}
		if e := authority.AuthorizeLegacyMappingWithin(sc, node); e != nil {
			return e
		}
		return repo.New().MapLegacyArchivesWithin(sc, node, proof)
	})
}
