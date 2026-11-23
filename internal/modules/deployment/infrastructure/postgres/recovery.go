package postgres

import (
	"context"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type Recovery struct{}

func (Recovery) QuarantineRecovery(sc transaction.Scope) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE deployment_upgrade_runs SET state='quarantined',document=jsonb_set(document,'{state}','"quarantined"');DELETE FROM deployment_node_events;DELETE FROM deployment_node_runtime;DELETE FROM deployment_desired;UPDATE deployment_nodes SET state='quarantined',enabled=false,legacy_origin=false;DELETE FROM deployment_execution_reports;DELETE FROM deployment_runtime;UPDATE deployment_releases SET state='failed',observed_version='',restored_version='';DELETE FROM deployment_target_runtime;DELETE FROM deployment_route_verifications;UPDATE deployment_generation SET generation=generation+1,dirty=false`)
		return e
	})
}
