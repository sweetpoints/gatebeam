package composition

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/statistics"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/modules/observability"
	"gatebeam/internal/modules/observability/application/archive"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/duckdb"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"gatebeam/internal/modules/observability/infrastructure/parquet"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	objectstore "gatebeam/internal/modules/observability/infrastructure/s3"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"time"
)

func historySecurity(p *pgxpool.Pool) statistics.Security {
	cat := &ingressaccess.Catalog{}
	a := identity.NewAccess(p, cat)
	cat.Ingress = ingress.New(p, ingressaccess.Authorizer{Identity: a})
	return statistics.Security{Access: a}
}

// NewHistory exposes the owner application to O5, without a socket or R2 secret.
func NewHistory(p *pgxpool.Pool, nodeMode ...bool) *query.Service {
	s := observability.NewHistory(p, historySecurity(p))
	if len(nodeMode) > 0 && nodeMode[0] {
		s.SetNodes(statistics.Nodes{Registry: deployment.NewNodes()})
	}
	return s
}
func runQuery(ctx context.Context, c bootstrap.Config) error {
	if c.QueryCredentialsFile == "" || c.QuerySocket == "" {
		return errors.New("query configuration incomplete")
	}
	credentials, e := objectstore.LoadConfig(c.QueryCredentialsFile)
	if e != nil {
		return e
	}
	return observability.RunQuery(ctx, c.QuerySocket, duckdb.Config{Binary: "/usr/local/bin/duckdb", Extension: "/opt/duckdb/httpfs.duckdb_extension", TempRoot: "/tmp/gatebeam-query", LocalRoot: c.QueryLocalDirectory, Endpoint: credentials.Endpoint, Bucket: credentials.Bucket, Region: credentials.Region, AccessKey: credentials.AccessKey, SecretKey: credentials.SecretKey})
}
func historyFailure(ctx context.Context, p *pgxpool.Pool, reason string, last *time.Time) {
	if ctx.Err() != nil || time.Since(*last) < time.Minute {
		return
	}
	*last = time.Now()
	receipt, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = repo.New().Failure(receipt, p, reason, *last)
	fmt.Fprintf(os.Stderr, "{\"component\":\"history_worker\",\"reason\":%q}\n", reason)
}
func runHistoryWorker(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) error {
	if c.QuerySocket == "" {
		workerComponentReady(ctx, true)
		<-ctx.Done()
		return nil
	}
	service := observability.NewHistoryCoordinator(p, historySecurity(p), c.QuerySocket)
	if c.RuntimeProtocol == 1 {
		service = observability.NewNodeHistoryCoordinator(p, historySecurity(p), c.QuerySocket, c.NodeID, c.NodeEpoch)
	}
	workerComponentReady(ctx, true)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastDiagnostic time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if !roleAccepts(ctx, lifecycle.GlobalJobs) {
				continue
			}
			if e := service.Step(ctx); e != nil {
				historyFailure(ctx, p, "query_unavailable", &lastDiagnostic)
			}
		}
	}
}
func runArchiveWorker(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) error {
	if c.ArchiveCredentialsFile == "" {
		workerComponentReady(ctx, true)
		<-ctx.Done()
		return nil
	}
	credentials, e := objectstore.LoadConfig(c.ArchiveCredentialsFile)
	if e != nil {
		return e
	}
	spool := c.LogSpoolDirectory
	if spool == "" {
		spool = "/var/lib/gatebeam/spool"
	}
	logs := c.LogDirectory
	if logs == "" {
		logs = "/var/lib/gatebeam/logs"
	}
	spoolWriter, e := parquet.New(spool)
	if c.RuntimeProtocol == 1 {
		spoolWriter, e = parquet.NewNode(spool, c.NodeID)
	}
	if e != nil {
		return e
	}
	store, e := objectstore.New(credentials, spool)
	if e != nil {
		return e
	}
	defer store.Close()
	tx := postgres.NewRunner(p)
	r := repo.New()
	if c.RuntimeProtocol == 1 {
		r = repo.NewNode(c.NodeID)
	}
	service := archive.New(tx, r, store)

	workerComponentReady(ctx, true)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastDiagnostic time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if !roleAccepts(ctx, lifecycle.LocalCleanup) {
			continue
		}
		step, done := context.WithTimeout(ctx, 65*time.Second)
		e = spoolWriter.Reconcile(step, func(ctx context.Context) (map[string]bool, error) {
			var refs map[string]bool
			err := tx.Within(ctx, func(sc transaction.Scope) error { var err error; refs, err = r.SpoolReferences(sc); return err })
			return refs, err
		})
		if e == nil {
			e = service.Step(step)
		}
		if e == nil {
			e = retireSources(step, tx, r, func() (retirementSource, error) {
				if c.RuntimeProtocol == 1 {
					return logfile.OpenNode(logs, c.NodeID)
				}
				return logfile.Open(logs)
			})
		}

		workerComponentReady(ctx, e == nil)
		if e != nil {
			historyFailure(ctx, p, "archive_unavailable", &lastDiagnostic)
		}
		done()
	}
}

type retirementSource interface {
	Discover(context.Context) ([]domain.Segment, error)
	RemoveRetired(domain.Segment) error
	Close() error
}
type retirementStore interface {
	BeginRetirement(transaction.Scope, domain.Segment) error
	Retirements(transaction.Scope) ([]repo.Retirement, error)
	FinishRetirement(transaction.Scope, string) error
}

// retireSources returns every unexpected stage failure to the archive loop's
// fixed-code diagnostic. An incomplete archive proof is the only normal skip.
func retireSources(ctx context.Context, tx transaction.Runner, r retirementStore, open func() (retirementSource, error)) (err error) {
	source, err := open()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	segments, err := source.Discover(ctx)
	if err != nil {
		return err
	}
	for _, seg := range segments {
		if !seg.Closed {
			continue
		}
		err = tx.Within(ctx, func(sc transaction.Scope) error { return r.BeginRetirement(sc, seg) })
		if err != nil && !errors.Is(err, domain.ErrIncomplete) {
			return err
		}
	}
	var pending []repo.Retirement
	if err = tx.Within(ctx, func(sc transaction.Scope) error { var e error; pending, e = r.Retirements(sc); return e }); err != nil {
		return err
	}
	for _, v := range pending {
		if err = source.RemoveRetired(v.Segment); err != nil {
			return err
		}
		if err = tx.Within(ctx, func(sc transaction.Scope) error { return r.FinishRetirement(sc, v.ID) }); err != nil {
			return err
		}
	}
	return nil
}
