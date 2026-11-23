// Package archive coordinates immutable upload, manifest commit and local cleanup.
package archive

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
)

type Store interface {
	Upload(context.Context, domain.Batch) (domain.Manifest, error)
	Cleanup(domain.Object) error
	Delete(context.Context, domain.Object) error
}
type Manifests interface {
	PendingWithin(transaction.Scope) (domain.Batch, bool, error)
	CommitManifestWithin(transaction.Scope, domain.Manifest) error
	CleanedWithin(transaction.Scope, string) error
}
type Service struct {
	tx        transaction.Runner
	manifests Manifests
	store     Store
}

func New(tx transaction.Runner, m Manifests, s Store) *Service { return &Service{tx, m, s} }
func (s *Service) Step(ctx context.Context) error {
	var b domain.Batch
	var found bool
	e := s.tx.Within(ctx, func(sc transaction.Scope) error { var e error; b, found, e = s.manifests.PendingWithin(sc); return e })
	if e != nil || !found {
		return e
	}
	m, e := s.store.Upload(ctx, b)
	if e != nil {
		return e
	}
	if e = s.tx.Within(ctx, func(sc transaction.Scope) error { return s.manifests.CommitManifestWithin(sc, m) }); e != nil {
		return e
	}
	if m, ok := s.manifests.(interface {
		CleanupWithin(transaction.Scope, domain.Batch, func() error) error
	}); ok {
		err := s.tx.Within(ctx, func(sc transaction.Scope) error {
			return m.CleanupWithin(sc, b, func() error {
				for _, o := range b.Objects {
					if e := s.store.Cleanup(o); e != nil {
						return e
					}
				}
				return nil
			})
		})
		if errors.Is(err, domain.ErrQueryBusy) {
			return nil
		}
		return err
	}
	for _, o := range b.Objects {
		if e = s.store.Cleanup(o); e != nil {
			return e
		}
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return s.manifests.CleanedWithin(sc, b.ID) })
}

type Deletion interface {
	BeginDeleteWithin(transaction.Scope, string) ([]domain.Object, error)
	FinishDeleteWithin(transaction.Scope, string) error
}

// Delete coordinates the manifest lifecycle. Existing queued/running snapshot
// readers must finish or expire before any referenced object can be removed.
func (s *Service) Delete(ctx context.Context, id string) error {
	d, ok := s.manifests.(Deletion)
	if !ok {
		return domain.ErrInvalid
	}
	var objects []domain.Object
	e := s.tx.Within(ctx, func(sc transaction.Scope) error { var e error; objects, e = d.BeginDeleteWithin(sc, id); return e })
	if e != nil {
		return e
	}
	for _, o := range objects {
		if e = s.store.Delete(ctx, o); e != nil {
			return e
		}
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return d.FinishDeleteWithin(sc, id) })
}
