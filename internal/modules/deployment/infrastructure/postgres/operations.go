package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/application/runtime"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ProgressWithin(sc transaction.Scope, id, stage, cause string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO deployment_execution_reports(release_id,stage,cause) VALUES($1,$2,$3) ON CONFLICT(release_id) DO UPDATE SET stage=excluded.stage,cause=excluded.cause,updated_at=clock_timestamp()`, id, stage, cause)
		return e
	})
}
func (s *Store) ExecutionWithin(sc transaction.Scope, id string) (out release.ExecutionReport, err error) {
	out.Stage = "unavailable"
	out.Cause = "unavailable"
	out.JobState = "unavailable"
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT stage,cause,updated_at FROM deployment_execution_reports WHERE release_id=$1`, id).Scan(&out.Stage, &out.Cause, &out.UpdatedAt)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if out.Stage != "unavailable" && !release.ValidProgress(out.Stage, out.Cause) {
			out.Stage = "unavailable"
			out.Cause = "unavailable"
		}
		e = tx.QueryRow(ctx, `SELECT status,attempt FROM jobs WHERE kind='deployment.apply' AND key=$1`, id).Scan(&out.JobState, &out.Attempt)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		var body []byte
		e = tx.QueryRow(ctx, `SELECT e.body FROM deployment_route_verifications e JOIN deployment_runtime a ON a.artifact_id=e.artifact_id AND a.version=e.version||'/'||e.generation WHERE a.release_id=$1 ORDER BY e.checked_at DESC LIMIT 1`, id).Scan(&body)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil {
			var report runtime.RouteVerification
			if e = json.Unmarshal(body, &report); e != nil {
				return e
			}
			out.RouteVerification = &report
		}
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployment_runtime WHERE release_id=$1)`, id).Scan(&out.ConfigApplied)
	})
	return
}
