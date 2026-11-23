package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability"
	"gatebeam/internal/modules/observability/domain"
	observabilitypg "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"time"
)

// runLogWorker owns an independent bounded loop. It never claims edge or
// certificate jobs and never delays health/DNS checks. Volumes are process config.
func runLogWorker(ctx context.Context, cfg bootstrap.Config, p *pgxpool.Pool) error {
	logs, spool := cfg.LogDirectory, cfg.LogSpoolDirectory
	if logs == "" {
		logs = "/var/lib/gatebeam/logs"
	}
	if spool == "" {
		spool = "/var/lib/gatebeam/spool"
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastDiagnostic time.Time
	var nextRotate time.Time
	cursor := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		step, done := context.WithTimeout(ctx, 10*time.Second)
		collector, source, e := observability.NewIngestor(p, logs, spool)
		if cfg.RuntimeProtocol == 1 {
			if source != nil {
				source.Close()
			}
			collector, source, e = observability.NewNodeIngestor(p, logs, spool, cfg.NodeID)
		}
		if e == nil {
			segments, err := source.Discover(step)
			e = err
			if e == nil && len(segments) > 0 {
				cursor %= len(segments)
				_, e = collector.Ingest(step, segments[cursor])
				cursor++
			}
			source.Close()
		}
		workerComponentReady(ctx, e == nil)
		now := time.Now()
		if e == nil && now.After(nextRotate) {
			key := "observability/" + now.UTC().Truncate(time.Minute).Format(time.RFC3339)
			if cfg.RuntimeProtocol == 1 {
				e = postgres.NewRunner(p).Within(step, func(sc transaction.Scope) error {
					_, err := jobs.New(p).EnqueueTargetWithin(sc, "deployment.node.rotate_logs.v1", key, json.RawMessage(`{}`), jobs.ClaimTarget{NodeID: cfg.NodeID, Epoch: cfg.NodeEpoch})
					return err
				})
			} else {
				_, e = jobs.New(p).Enqueue(step, "deployment.rotate_logs", key, json.RawMessage(`{}`))
			}
			if e == nil {
				nextRotate = now.Add(time.Minute)
			}
		}
		if e != nil && ctx.Err() == nil && now.Sub(lastDiagnostic) >= time.Minute {
			reason := "ingest_unavailable"
			if errors.Is(e, domain.ErrCapacity) {
				reason = "capacity"
			}
			if errors.Is(e, domain.ErrSourceChanged) {
				reason = "source_changed"
			}
			// Fixed reason only. File names, raw errors and input records are excluded.
			_ = observabilitypg.New().Failure(step, p, reason, now)
			fmt.Fprintf(os.Stderr, "{\"component\":\"log_worker\",\"reason\":%q}\n", reason)
			lastDiagnostic = now
		}
		done()
	}
}
