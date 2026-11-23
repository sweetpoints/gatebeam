package query

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Operations interface {
	ListWithin(transaction.Scope, ActorRef, int, int) ([]Input, error)
	CancelWithin(transaction.Scope, string) error
}

// Listing describes the scanned window, not the count remaining after ACL
// filtering. A caller may receive no visible jobs and still have continuation.
type Listing struct {
	Items      []Job
	HasMore    bool
	NextOffset int
}

func (s *Service) List(ctx context.Context, a ActorRef, limit, offset int) (out Listing, err error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return Listing{}, domain.ErrInvalid
	}
	ctx, c := context.WithTimeout(ctx, 5*time.Second)
	defer c()
	out.Items = []Job{}
	err = s.tx.Within(ctx, func(sc transaction.Scope) error {
		guard, ok := s.security.(interface {
			GuardWithin(transaction.Scope, ActorRef) error
		})
		if !ok {
			return domain.ErrDenied
		}
		if e := guard.GuardWithin(sc, a); e != nil {
			return e
		}
		r, ok := s.jobs.(Operations)
		if !ok {
			return domain.ErrIncomplete
		}
		rows, e := r.ListWithin(sc, a, limit+1, offset)
		if e != nil {
			return e
		}
		// At most limit+1 raw rows are read. The lookahead is used only for
		// continuation; no unauthorized job identity or details leave this use case.
		out.HasMore = len(rows) > limit
		if out.HasMore {
			out.NextOffset = offset + limit
			rows = rows[:limit]
		}
		for _, in := range rows {
			if in.Actor != a {
				continue
			}
			if e = s.security.RequireWithin(sc, a, in.Filter.SiteIDs); e != nil {
				if errors.Is(e, domain.ErrDenied) {
					continue
				}
				return e
			}
			out.Items = append(out.Items, in.Job)
		}
		return nil
	})
	return
}
func (s *Service) Cancel(ctx context.Context, a ActorRef, id string) error {
	ctx, c := context.WithTimeout(ctx, 5*time.Second)
	defer c()
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		in, _, e := s.jobs.FetchWithin(sc, id)
		if e != nil {
			return e
		}
		if in.Actor != a {
			return domain.ErrDenied
		}
		if e = s.security.RequireWithin(sc, a, in.Filter.SiteIDs); e != nil {
			return e
		}
		r, ok := s.jobs.(Operations)
		if !ok {
			return domain.ErrIncomplete
		}
		return r.CancelWithin(sc, id)
	})
}
