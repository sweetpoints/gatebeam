package postgres

import (
	"context"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
)

func (*Store) RecordOutcome(sc transaction.Scope, v string, state domain.State, version, restored string) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		n, e := q.RecordOutcome(ctx, dbgen.RecordOutcomeParams{ID: id(v), State: string(state), ObservedVersion: version, RestoredVersion: restored})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrNotFound
		}
		return nil
	})
}
func (*Store) RecordVerified(sc transaction.Scope, v, artifact, version string) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		return q.RecordVerified(ctx, dbgen.RecordVerifiedParams{ReleaseID: id(v), ArtifactID: artifact, Version: version})
	})
}
func (*Store) CurrentVerified(sc transaction.Scope) (out release.VerifiedReceipt, err error) {
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		r, e := q.CurrentVerified(ctx)
		if e != nil {
			return e
		}
		out = release.VerifiedReceipt{ReleaseID: r.ReleaseID, ArtifactID: r.ArtifactID, Version: r.Version}
		return nil
	})
	return
}
