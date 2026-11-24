package acme

import (
	"context"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
)

func (s *OrderService) Challenge(ctx context.Context, ref AccountRef, id, cid string) (domain.Order, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var before domain.Order
	var account domain.Account
	var ch domain.Challenge
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		var e error
		before, account, _, e = s.load(sc, ref, id)
		if e != nil {
			return e
		}
		for _, c := range before.Challenges {
			if c.ID == cid {
				ch = c
				break
			}
		}
		if ch.ID == "" {
			return ErrOrderNotFound
		}
		if ch.Status == "valid" {
			return nil
		}
		if before.Status != "pending" || ch.Status != "pending" || !s.now().Before(before.Expires) {
			return ErrOrderNotReady
		}
		return nil
	})
	if e != nil {
		return domain.Order{}, e
	}
	if ch.Status == "valid" {
		return before, nil
	}
	if s.validator == nil {
		return domain.Order{}, ErrOrderNotReady
	}
	// No database locks, connection or transaction are held during network I/O.
	proof := s.validator.Validate(ctx, ch.Name, ch.Token, ch.Token+"."+account.Thumbprint)
	var out domain.Order
	e = s.tx.Within(ctx, func(sc transaction.Scope) error {
		o, a, _, e := s.load(sc, ref, id)
		if e != nil {
			return e
		}
		if a.Revision != account.Revision {
			return ErrDenied
		}
		matched := false
		for _, current := range o.Challenges {
			if current.ID == ch.ID && current.Revision == ch.Revision && current.Status == ch.Status && current.Token == ch.Token && current.Name == ch.Name {
				matched = true
			}
		}
		if !matched {
			return ErrDenied
		}
		revision := o.Revision
		if e = o.CompleteChallenge(cid, proof == nil, s.now()); e != nil {
			return ErrOrderNotReady
		}
		if e = s.repo.SaveOrder(sc, o, revision); e != nil {
			return e
		}
		out = o
		return nil
	})
	if e != nil {
		return domain.Order{}, e
	}
	return out, nil
}
