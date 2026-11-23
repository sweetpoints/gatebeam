package application

import (
	"context"
	"gatebeam/internal/platform/transaction"
	"time"
)

// ObserveExpiry is called for immutable published revisions, even when newer
// drafts exist. It inspects current authority independently of renewal errors.
func (s *Service) ObserveExpiry(ctx context.Context, id string, revision int64) error {
	recorder, ok := s.repo.(interface {
		ExpiryWithin(transaction.Scope, string, int64, time.Time) error
	})
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.WriteLock(sc); e != nil {
			return e
		}
		return recorder.ExpiryWithin(sc, id, revision, s.now())
	})
}

func (s *Service) observeCurrentExpiry(ctx context.Context) error {
	recorder, ok := s.repo.(interface {
		ExpiryCurrentWithin(transaction.Scope, time.Time) error
	})
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.WriteLock(sc); e != nil {
			return e
		}
		return recorder.ExpiryCurrentWithin(sc, s.now())
	})
}
