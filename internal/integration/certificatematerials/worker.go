package certificatematerials

import (
	"context"
	"errors"
	cert "gatebeam/internal/modules/certificates/application"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	"time"
)

type Published interface {
	Snapshot(context.Context) (app.Snapshot, error)
}
type Lifecycle interface {
	EnsureRevision(context.Context, string, int64) (cert.Version, error)
	PrepareStatus(context.Context, string, int64) error
	CleanupChallenges(context.Context) error
	PrepareCurrent(context.Context) error
}

// Worker renews current published references and prepares explicitly enabled
// management resources. Only the published snapshot can authorize activation.
type Worker struct {
	Published    Published
	Certificates Lifecycle
}

func (w Worker) Step(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cleanupError := w.Certificates.CleanupChallenges(ctx)
	snapshot, e := w.Published.Snapshot(ctx)
	if e != nil {
		return errors.Join(cleanupError, e, w.Certificates.PrepareCurrent(ctx))
	}
	seen := map[app.Material]bool{}
	failures := cleanupError
	for _, ref := range release.Materials(snapshot) {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		switch ref.Kind {
		case "certificate":
			if expiry, ok := w.Certificates.(interface {
				ObserveExpiry(context.Context, string, int64) error
			}); ok {
				failures = errors.Join(failures, expiry.ObserveExpiry(ctx, ref.ID, ref.Revision))
			}
			_, e = w.Certificates.EnsureRevision(ctx, ref.ID, ref.Revision)
		case "trust", "origin_pull_trust":
			e = w.Certificates.PrepareStatus(ctx, ref.ID, ref.Revision)
		}
		if e != nil {
			failures = errors.Join(failures, e)
		}
		if ctx.Err() != nil {
			return errors.Join(failures, ctx.Err())
		}
	}
	return errors.Join(failures, w.Certificates.PrepareCurrent(ctx))
}
