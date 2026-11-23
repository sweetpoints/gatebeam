package query

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
	"strconv"
	"sync/atomic"
	"time"
)

type Service struct {
	nodes    NodeTargets
	tx       transaction.Runner
	security Security
	jobs     Jobs
}

func New(tx transaction.Runner, s Security, j Jobs) *Service {
	return &Service{tx: tx, security: s, jobs: j}
}
func (s *Service) Submit(ctx context.Context, a ActorRef, f Filter) (Job, error) {
	if e := f.Validate(); e != nil {
		return Job{}, e
	}
	ctx, c := context.WithTimeout(ctx, 5*time.Second)
	defer c()
	var j Job
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.security.RequireWithin(sc, a, f.SiteIDs); e != nil {
			return e
		}
		var targets []LocalNode
		if f.Source == "local" && s.nodes != nil {
			var e error
			targets, e = s.nodes.TargetsWithin(sc)
			if e != nil {
				return e
			}
			if len(targets) == 0 || len(targets) > 2 {
				return domain.ErrIncomplete
			}
		}
		var e error
		j, e = s.jobs.SubmitWithin(sc, a, f)
		if e != nil {
			return e
		}
		if len(targets) > 0 {
			repository, ok := s.jobs.(interface {
				PrepareLocalWithin(transaction.Scope, Job, []LocalNode) (Job, error)
			})
			if !ok {
				return domain.ErrIncomplete
			}
			j, e = repository.PrepareLocalWithin(sc, j, targets)
		}
		return e
	})
	return j, e
}
func (s *Service) Fetch(ctx context.Context, a ActorRef, id, cursor string) (Page, error) {
	offset := 0
	var e error
	if cursor != "" {
		offset, e = strconv.Atoi(cursor)
		if e != nil || offset < 0 || offset > domain.MaxQueryRows || offset%100 != 0 {
			return Page{}, domain.ErrInvalid
		}
	}
	ctx, c := context.WithTimeout(ctx, 5*time.Second)
	defer c()
	var out Page
	e = s.tx.Within(ctx, func(sc transaction.Scope) error {
		in, rows, e := s.jobs.FetchWithin(sc, id)
		if e != nil {
			return e
		}
		if in.Actor != a {
			return domain.ErrDenied
		}
		if e = s.security.RequireWithin(sc, a, in.Filter.SiteIDs); e != nil {
			return e
		}
		if expirer, ok := s.jobs.(interface{ ExpireLocalWithin(transaction.Scope) error }); ok && in.Job.State == "coordinating" {
			if e = expirer.ExpireLocalWithin(sc); e != nil {
				return e
			}
			in, rows, e = s.jobs.FetchWithin(sc, id)
			if e != nil {
				return e
			}
		}
		out.Job = in.Job
		if in.Job.ExpiresAt.Before(time.Now()) {
			return domain.ErrIncomplete
		}
		if offset > len(rows) {
			return domain.ErrInvalid
		}
		end := min(offset+100, len(rows))
		out.Rows = rows[offset:end]
		if end < len(rows) {
			out.Cursor = strconv.Itoa(end)
		}
		return nil
	})
	return out, e
}

// Coordinator is assembled only in worker. No engine or cloud credential enters
// the API Service. Every lease execution rechecks the original live credential.
type Coordinator struct {
	service *Service
	engine  Engine
}

func NewCoordinator(s *Service, e Engine) *Coordinator { return &Coordinator{s, e} }
func (c *Coordinator) Step(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	s := c.service
	var in Input
	var found bool
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		var e error
		if expirer, ok := s.jobs.(interface{ ExpireLocalWithin(transaction.Scope) error }); ok {
			if e = expirer.ExpireLocalWithin(sc); e != nil {
				return e
			}
		}
		in, found, e = s.jobs.ClaimWithin(sc)
		return e
	})
	if e != nil || !found {
		return e
	}
	e = s.tx.Within(ctx, func(sc transaction.Scope) error { return s.security.RequireWithin(sc, in.Actor, in.Filter.SiteIDs) })
	var rows []domain.QueryRow
	code := ""
	if e != nil {
		code = "denied"
	} else {
		execute, cancelExecute := context.WithCancel(ctx)
		stopped := make(chan struct{})
		var cancelled atomic.Bool
		go func() {
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stopped:
					return
				case <-execute.Done():
					return
				case <-tick.C:
					check, done := context.WithTimeout(execute, time.Second)
					_ = s.tx.Within(check, func(sc transaction.Scope) error {
						if monitor, ok := s.jobs.(interface {
							LeaseCurrentWithin(transaction.Scope, Input) (bool, error)
						}); ok && in.Target.NodeID != "" {
							current, err := monitor.LeaseCurrentWithin(sc, in)
							if err == nil && !current {
								cancelled.Store(true)
								cancelExecute()
							}
							return err
						}
						fresh, _, err := s.jobs.FetchWithin(sc, in.Job.ID)
						if err == nil && (fresh.Job.State != "running" || fresh.Token != in.Token) {
							cancelled.Store(true)
							cancelExecute()
						}
						return err
					})
					done()
				}
			}
		}()
		rows, e = c.engine.Execute(execute, in.Filter, in.Objects)
		close(stopped)
		cancelExecute()
		if cancelled.Load() {
			return nil
		}
		if e != nil {
			code = "query_failed"
			if errors.Is(e, domain.ErrCapacity) {
				code = "capacity"
			}
			if errors.Is(e, domain.ErrQueryTimeout) {
				code = "timeout"
			}
			if errors.Is(e, domain.ErrQueryBusy) {
				code = "busy"
			}
			rows = nil
		}
	}
	// Use a fresh bounded context for a cancellation receipt, not a cancelled lease.
	finish, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer done()
	return s.tx.Within(finish, func(sc transaction.Scope) error {
		err := s.jobs.CompleteWithin(sc, in, rows, code)
		if errors.Is(err, domain.ErrIncomplete) {
			fresh, _, readErr := s.jobs.FetchWithin(sc, in.Job.ID)
			if readErr == nil && fresh.Job.State == "cancelled" {
				return nil
			}
		}
		return err
	})
}

func (s *Service) SetNodes(nodes NodeTargets) { s.nodes = nodes }
