package recovery

import (
	"context"
	cert "gatebeam/internal/modules/certificates/application"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	deployment "gatebeam/internal/modules/deployment/application/recovery"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	identity "gatebeam/internal/modules/identity/application"
	identitypg "gatebeam/internal/modules/identity/infrastructure/postgres"
	notification "gatebeam/internal/modules/notification/application"
	notificationpg "gatebeam/internal/modules/notification/infrastructure/postgres"
	obs "gatebeam/internal/modules/observability/application/query"
	obspg "gatebeam/internal/modules/observability/infrastructure/postgres"
	pki "gatebeam/internal/modules/pki/application"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func quarantine(ctx context.Context, p *pgxpool.Pool) error {
	return platform.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		if e := identity.RecoverWithin(sc, identitypg.New()); e != nil {
			return e
		}
		if e := cert.RecoverWithin(sc, certpg.Recovery{}); e != nil {
			return e
		}
		if e := pki.RecoverWithin(sc, pkipg.New()); e != nil {
			return e
		}
		if e := deployment.Within(sc, deploymentpg.Recovery{}); e != nil {
			return e
		}
		if e := notification.RecoverWithin(sc, notificationpg.Recovery{}); e != nil {
			return e
		}
		if e := obs.RecoverWithin(sc, obspg.New()); e != nil {
			return e
		}
		// Platform queues are inert on recovery; old work must never resume.
		return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `DELETE FROM job_attempts;DELETE FROM jobs;DELETE FROM outbox;DELETE FROM consumer_receipts`)
			return e
		})
	})
}
