package application

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

// PrepareCurrent provisions explicitly enabled management resources before first
// publication. It never reads routing drafts or activates a deployment. Durable
// leases and retry times provide bounded, restart-safe scheduling and fairness.
func (s *Service) PrepareCurrent(ctx context.Context) error {
	if e := s.observeCurrentExpiry(ctx); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var due []Resource
	if e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.ReadLock(sc); e != nil {
			return e
		}
		var e error
		due, e = s.repo.PreparationDue(sc)
		return e
	}); e != nil {
		return e
	}
	return s.prepare(ctx, due, true)
}

func (s *Service) PrepareStatus(ctx context.Context, id string, revision int64) error {
	var record Record
	if e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.repo.ReadLock(sc); e != nil {
			return e
		}
		var e error
		record, e = s.repo.Read(sc, "trust", id, revision)
		return e
	}); e != nil {
		return e
	}
	return s.prepare(ctx, []Resource{record.Resource}, false)
}
func (s *Service) prepare(ctx context.Context, due []Resource, current bool) error {
	var failures error
	for _, resource := range due {
		if ctx.Err() != nil {
			return errors.Join(failures, ctx.Err())
		}
		token, e := s.crypto.NewID()
		if e != nil {
			return e
		}
		var attempt domain.Attempt
		e = s.tx.Within(ctx, func(sc transaction.Scope) error {
			if e := s.graph.GuardWithin(sc); e != nil {
				return e
			}
			if e := s.repo.WriteLock(sc); e != nil {
				return e
			}
			revision := resource.Revision
			if current {
				revision = 0
			}
			fresh, e := s.repo.Read(sc, resource.Kind, resource.ID, revision)
			if e != nil || !fresh.Enabled || fresh.Revision != resource.Revision {
				return domain.ErrConflict
			}
			attempt, e = s.repo.ClaimPreparation(sc, resource, token, s.now().Add(2*time.Minute))
			return e
		})
		if e != nil {
			if !errors.Is(e, domain.ErrNotFound) && !errors.Is(e, domain.ErrConflict) {
				failures = errors.Join(failures, e)
			}
			continue
		}
		next := s.now().Add(time.Minute)
		switch resource.Kind {
		case "spec":
			_, e = s.EnsureRevision(ctx, resource.ID, resource.Revision)
		case "trust":
			e = s.RefreshStatus(ctx, resource.ID, resource.Revision)
			if e == nil {
				e = s.tx.Within(ctx, func(sc transaction.Scope) error {
					if e := s.repo.ReadLock(sc); e != nil {
						return e
					}
					var trust TrustBundle
					if e := json.Unmarshal(resource.Body, &trust); e != nil {
						return e
					}
					status, e := s.repo.Status(sc, resource.ID, resource.Revision, s.status.ProfileDigest(trust.StatusProfile))
					if e != nil {
						return e
					}
					next = status.ValidUntil.Add(-time.Minute)
					if !next.After(s.now()) {
						next = s.now().Add(5 * time.Second)
					}
					return nil
				})
			}
		default:
			e = domain.ErrInvalid
		}
		result := domain.Attempt{NextAttempt: next}
		if e != nil {
			result = attempt.Failed(s.now())
			failures = errors.Join(failures, e)
		}
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		finishError := s.tx.Within(finish, func(sc transaction.Scope) error {
			if e := s.repo.WriteLock(sc); e != nil {
				return e
			}
			return s.repo.FinishPreparation(sc, resource, token, result)
		})
		cancel()
		failures = errors.Join(failures, finishError)
	}
	return failures
}
