package acme

import (
	"context"
	"gatebeam-ca/internal/platform/transaction"
	"time"
)

// Nonces commits independently of business transactions. A failed enrollment,
// audit or rollover cannot revive a nonce whose signature was already verified.
type Nonces struct {
	tx     transaction.Runner
	repo   Repository
	random Random
	now    Clock
}

func NewNonces(tx transaction.Runner, r Repository, random Random, now Clock) *Nonces {
	if now == nil {
		now = time.Now
	}
	return &Nonces{tx, r, random, now}
}
func (s *Nonces) Issue(ctx context.Context) (string, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	n, e := s.random.Random()
	if e != nil {
		return "", e
	}
	e = s.tx.Within(ctx, func(sc transaction.Scope) error {
		return s.repo.AddNonce(sc, s.random.Digest(n), s.now().Add(10*time.Minute))
	})
	if e != nil {
		return "", e
	}
	return n, nil
}
func (s *Nonces) Consume(ctx context.Context, n string) error {
	if len(n) != 43 {
		return ErrBadNonce
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return s.repo.ConsumeNonce(sc, s.random.Digest(n), s.now()) })
}
