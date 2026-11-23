package postgres

import (
	"context"
	"errors"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"time"
)

var ErrInvalidScope = errors.New("invalid or expired transaction scope")

type scope struct {
	ctx    context.Context
	tx     pgx.Tx
	mu     sync.Mutex
	active bool
}

func (s *scope) Context() context.Context { return s.ctx }

type Runner struct{ pool *pgxpool.Pool }

func NewRunner(p *pgxpool.Pool) *Runner { return &Runner{p} }
func (r *Runner) Within(ctx context.Context, fn func(transaction.Scope) error) error {
	tx, e := r.pool.Begin(ctx)
	if e != nil {
		return e
	}
	s := &scope{ctx: ctx, tx: tx, active: true}
	defer func() {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	if e = fn(s); e != nil {
		return e
	}
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
	return tx.Commit(ctx)
}

// Use validates the opaque scope and holds it exclusively during an adapter call.
// Callers must not retain tx or use Scope concurrently; no pool fallback exists.
func Use(sc transaction.Scope, fn func(context.Context, pgx.Tx) error) error {
	s, ok := sc.(*scope)
	if !ok || s == nil {
		return ErrInvalidScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.ctx.Err() != nil {
		return ErrInvalidScope
	}
	return fn(s.ctx, s.tx)
}
