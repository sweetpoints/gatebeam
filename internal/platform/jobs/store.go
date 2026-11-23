// Package jobs persists bounded, reclaimable platform jobs.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/platform/jobs/dbgen"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNoJob = errors.New("no eligible job")
var ErrDraining = errors.New("worker is draining")
var ErrLeaseLost = errors.New("job lease lost")

type Job struct {
	Target     ClaimTarget
	ID, Kind   string
	Payload    json.RawMessage
	LeaseToken string
	Deadline   time.Time
	Attempt    int
}
type Store struct {
	runner   *postgres.Runner
	draining atomic.Bool
	claimMu  sync.RWMutex
}

func New(p *pgxpool.Pool) *Store { return &Store{runner: postgres.NewRunner(p)} }
func (s *Store) Enqueue(ctx context.Context, kind, key string, payload json.RawMessage) (id string, err error) {
	err = s.runner.Within(ctx, func(sc transaction.Scope) error {
		var e error
		id, e = s.EnqueueWithin(sc, kind, key, payload)
		return e
	})
	return
}
func (s *Store) EnqueueWithin(sc transaction.Scope, kind, key string, payload json.RawMessage) (id string, err error) {
	if strings.Contains(kind, ".node.") {
		return "", errors.New("node job requires an explicit target")
	}
	err = postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		id, e = dbgen.New(tx).Enqueue(ctx, dbgen.EnqueueParams{Kind: kind, Key: key, Payload: payload})
		return e
	})
	return
}
func (s *Store) Claim(ctx context.Context, worker string, lease time.Duration) (job Job, err error) {
	s.claimMu.RLock()
	defer s.claimMu.RUnlock()
	if s.draining.Load() || !acceptGlobal(ctx) {
		return job, ErrDraining
	}
	if worker == "" || lease <= 0 || lease > time.Hour {
		return job, errors.New("invalid worker or lease duration")
	}
	err = s.runner.Within(ctx, func(sc transaction.Scope) error {
		return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			q := dbgen.New(tx)
			if e := q.Exhaust(ctx); e != nil {
				return e
			}
			row, e := q.Claim(ctx, dbgen.ClaimParams{Worker: pgtype.Text{String: worker, Valid: true}, LeaseSeconds: lease.Seconds()})
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			if e != nil {
				return e
			}
			if e = q.RecordAttempt(ctx, dbgen.RecordAttemptParams{JobID: row.ID, Attempt: row.Attempt, LeaseToken: row.LeaseToken.String, Worker: worker}); e != nil {
				return e
			}
			job = Job{ID: row.ID, Kind: row.Kind, Payload: row.Payload, LeaseToken: row.LeaseToken.String, Deadline: row.Deadline.Time, Attempt: int(row.Attempt)}
			return nil
		})
	})
	if err == nil && job.ID == "" {
		err = ErrNoJob
	}
	return
}
func (s *Store) Complete(ctx context.Context, id, token string) error {
	return s.runner.Within(ctx, func(sc transaction.Scope) error { return s.CompleteWithin(sc, id, token) })
}
func (s *Store) CompleteWithin(sc transaction.Scope, id, token string) error {
	return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		n, e := q.Complete(ctx, dbgen.CompleteParams{ID: id, LeaseToken: pgtype.Text{String: token, Valid: true}})
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrLeaseLost
		}
		return q.CompleteAttempt(ctx, dbgen.CompleteAttemptParams{JobID: id, LeaseToken: token})
	})
}
func (s *Store) FenceWithin(sc transaction.Scope, id, token string) error {
	return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := dbgen.New(tx).Fence(ctx, dbgen.FenceParams{ID: id, LeaseToken: pgtype.Text{String: token, Valid: true}})
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrLeaseLost
		}
		return e
	})
}

// ClaimKinds is a bounded executor partition; it neither claims nor expires
// foreign work. The process composition supplies its fixed allowlist.
func (s *Store) ClaimKinds(ctx context.Context, worker string, lease time.Duration, kinds []string) (job Job, err error) {
	s.claimMu.RLock()
	defer s.claimMu.RUnlock()
	if s.draining.Load() || !acceptGlobal(ctx) {
		return job, ErrDraining
	}
	if worker == "" || lease <= 0 || lease > time.Hour || len(kinds) == 0 || len(kinds) > 16 {
		return job, errors.New("invalid restricted claim")
	}
	for _, k := range kinds {
		if k == "" || len(k) > 128 {
			return job, errors.New("invalid job kind")
		}
	}
	err = s.runner.Within(ctx, func(sc transaction.Scope) error {
		return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			q := dbgen.New(tx)
			if e := q.ExhaustKinds(ctx, kinds); e != nil {
				return e
			}
			row, e := q.ClaimKinds(ctx, dbgen.ClaimKindsParams{Worker: pgtype.Text{String: worker, Valid: true}, LeaseSeconds: lease.Seconds(), Kinds: kinds})
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			if e != nil {
				return e
			}
			if e = q.RecordAttempt(ctx, dbgen.RecordAttemptParams{JobID: row.ID, Attempt: row.Attempt, LeaseToken: row.LeaseToken.String, Worker: worker}); e != nil {
				return e
			}
			job = Job{ID: row.ID, Kind: row.Kind, Payload: row.Payload, LeaseToken: row.LeaseToken.String, Deadline: row.Deadline.Time, Attempt: int(row.Attempt)}
			return nil
		})
	})
	if err == nil && job.ID == "" {
		err = ErrNoJob
	}
	return
}

func acceptGlobal(ctx context.Context) bool {
	state := lifecycle.FromContext(ctx)
	return state == nil || state.Accepts(lifecycle.GlobalJobs)
}
func acceptCleanup(ctx context.Context) bool {
	state := lifecycle.FromContext(ctx)
	return state == nil || state.Accepts(lifecycle.LocalCleanup)
}
