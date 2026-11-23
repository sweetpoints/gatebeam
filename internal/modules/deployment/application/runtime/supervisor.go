package runtime

import (
	"context"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"time"
)

var ErrNotRunning = errors.New("Nginx is not running")
var ErrReconcile = errors.New("local application requires reconciliation")

type ApplyResult struct {
	Cause                           string
	Version, State, RestoredVersion string
	Verification                    *RouteVerification
}
type ObservedState struct{ Version, State string }
type Supervisor struct {
	process   Process
	artifacts ArtifactStore
	journal   Journal
	compiler  Compiler
	verifier  PostApplyVerifier
	authority PublicationAuthority
	boot      BootStore
	node      domain.NodeRef
}

func (s *Supervisor) SetBootStore(store BootStore, node domain.NodeRef) {
	s.boot, s.node = store, node
}

func NewSupervisor(p Process, a ArtifactStore, j Journal, c Compiler, auth PublicationAuthority, verification ...PostApplyVerifier) *Supervisor {
	s := &Supervisor{process: p, artifacts: a, journal: j, compiler: c, authority: auth}
	if len(verification) > 0 {
		s.verifier = verification[0]
	}
	return s
}
func (s *Supervisor) Apply(ctx context.Context, id string) (result ApplyResult, err error) {
	cause := "unavailable"
	progress := func(state, why string) {
		cause = why
		if p, ok := s.authority.(interface {
			ReportProgress(context.Context, string, string, string) error
		}); ok {
			_ = p.ReportProgress(ctx, id, state, why)
		}
	}
	defer func() {
		if err != nil {
			result.Cause = cause
			if result.State == "restore_failed" {
				result.Cause = "restore_failed"
			}
			if result.State == "" {
				result.State = "failed"
			}
		} else {
			result.Cause = "none"
		}
	}()
	progress("preparing", "none")
	cause = "unavailable"
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	unlock, e := s.artifacts.Lock(ctx)
	if e != nil {
		return result, e
	}
	defer unlock()
	previous, e := s.journal.Load(ctx)
	if e != nil {
		return result, e
	}
	if previous.ReceiptPending {
		return result, ErrReconcile
	}
	old, e := s.process.Observe(ctx)
	if e != nil && !errors.Is(e, ErrNotRunning) {
		return result, e
	}
	cause = "authority_or_preparation_failed"
	plan, e := s.authority.Prepare(ctx, id)
	if e != nil {
		return ApplyResult{Version: old, State: string(domain.Failed)}, e
	}
	j := domain.ApplyJournal{CandidateID: id, PreviousVersion: old, Version: plan.Snapshot.Version + "/" + plan.Runtime.Generation, State: domain.Queued}
	step := func(state domain.State) error {
		if e := j.Advance(state); e != nil {
			return e
		}
		err := s.journal.Save(ctx, j)
		if err != nil {
			cause = "unavailable"
		}
		return err
	}
	fail := func(cause error) (ApplyResult, error) {
		j.State = domain.Failed
		j.ReceiptPending = false
		return ApplyResult{Version: old, State: string(j.State)}, errors.Join(cause, s.journal.Save(ctx, j))
	}
	if e = step(domain.Preparing); e != nil {
		return result, e
	}
	cause = "compile_failed"
	artifact, e := s.compiler.Compile(plan.Snapshot, plan.Runtime)
	if e != nil {
		return fail(e)
	}
	j.ArtifactID = artifact.ID
	cause = "stage_failed"
	path, e := s.artifacts.Stage(ctx, artifact)
	if e != nil {
		return fail(e)
	}
	cause = "native_validation_failed"
	if e = s.process.Validate(ctx, path); e != nil {
		return fail(e)
	}
	if e = s.stageBoot(ctx, plan, artifact); e != nil {
		return fail(e)
	}
	if e = step(domain.Validated); e != nil {
		return result, e
	}
	progress("validated", "none")
	attempted := false
	// Authorization locks span at most 15 seconds, never worker drain. A native
	// success followed by DB failure is explicitly pending local reconciliation.
	guarded, done := context.WithTimeout(ctx, 15*time.Second)
	cause = "activation_or_observation_failed"
	e = s.authority.ActivateWithin(guarded, id, plan, func() error {
		j.ReceiptPending = true
		if e = step(domain.Applying); e != nil {
			return e
		}
		attempted = true
		if e = s.artifacts.Switch(guarded, artifact.ID); e != nil {
			return e
		}
		if e = s.process.Activate(guarded, j.Version); e != nil {
			return e
		}
		if e = step(domain.Verifying); e != nil {
			return e
		}
		actual, e := s.process.Observe(guarded)
		if e != nil {
			return e
		}
		if actual != j.Version {
			return ErrReconcile
		}
		return nil
	})
	done()
	var verification *RouteVerification
	locallyConfirmed := false
	if e == nil {
		progress("verifying", "none")
	}
	if e == nil && s.verifier != nil {
		cause = "route_verification_failed"
		report, err := s.verifier.Verify(ctx, plan, artifact.ID)
		verification = &report
		e = err
	}
	if e == nil {
		cause = "confirmation_failed"
		final, finish := context.WithTimeout(ctx, 15*time.Second)
		e = s.authority.Within(final, id, plan, func() error {
			actual, err := s.process.Observe(final)
			if err != nil {
				return err
			}
			if actual != j.Version {
				return ErrReconcile
			}
			if err := s.confirmBoot(final, artifact.ID, j.Version, plan.Runtime.Generation); err != nil {
				return err
			}
			locallyConfirmed = s.boot != nil
			return step(domain.Succeeded)
		})
		finish()
	}
	if e != nil {
		if locallyConfirmed {
			// A durable native confirmation is independent from the database
			// commit acknowledgement. Reconcile facts before further control work.
			return ApplyResult{Version: j.Version, State: "receipt_pending", Verification: verification}, e
		}
		if !attempted {
			return fail(e)
		}
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		progress("restoring", cause)
		observed, re := s.restore(recovery, &j)
		restored := ""
		if observed.State == string(domain.Restored) {
			restored = observed.Version
		}
		return ApplyResult{Version: observed.Version, State: observed.State, RestoredVersion: restored, Verification: verification}, errors.Join(e, re)
	}
	j.ReceiptPending = false
	if e = s.journal.Save(ctx, j); e != nil {
		return ApplyResult{Version: j.Version, State: string(domain.Succeeded), Verification: verification}, e
	}
	return ApplyResult{Version: j.Version, State: string(domain.Succeeded), Verification: verification}, nil
}
func (s *Supervisor) restore(ctx context.Context, j *domain.ApplyJournal) (ObservedState, error) {
	j.State = domain.Restoring
	j.ReceiptPending = true
	if e := s.journal.Save(ctx, *j); e != nil {
		return ObservedState{}, e
	}
	failure := func(e error) (ObservedState, error) {
		j.State = domain.RestoreFailed
		save := s.journal.Save(ctx, *j)
		actual, _ := s.process.Observe(ctx)
		return ObservedState{actual, string(j.State)}, errors.Join(e, save)
	}
	plan, e := s.authority.CurrentVerified(ctx)
	if e != nil {
		return failure(e)
	}
	artifact, e := s.compiler.Compile(plan.Snapshot, plan.Runtime)
	if e != nil {
		return failure(e)
	}
	path, e := s.artifacts.Stage(ctx, artifact)
	if e != nil {
		return failure(e)
	}
	if e = s.process.Validate(ctx, path); e != nil {
		return failure(e)
	}
	if e = s.stageBoot(ctx, plan, artifact); e != nil {
		return failure(e)
	}
	var actual string
	e = s.authority.RestoreActivateWithin(ctx, plan, func(effectCtx context.Context) error {
		if e := effectCtx.Err(); e != nil {
			return e
		}
		if e := s.artifacts.Switch(effectCtx, artifact.ID); e != nil {
			return e
		}
		if e := effectCtx.Err(); e != nil {
			return e
		}
		if e := s.process.Activate(effectCtx, plan.Snapshot.Version+"/"+plan.Runtime.Generation); e != nil {
			return e
		}
		if e := effectCtx.Err(); e != nil {
			return e
		}
		var e error
		actual, e = s.process.Observe(effectCtx)
		if e != nil {
			return e
		}
		if actual != plan.Snapshot.Version+"/"+plan.Runtime.Generation {
			return ErrReconcile
		}
		return nil
	})
	if e == nil && s.verifier != nil {
		_, e = s.verifier.Verify(ctx, plan, artifact.ID)
	}
	if e == nil {
		e = s.authority.WithRestore(ctx, plan, func(final context.Context) error {
			v, err := s.process.Observe(final)
			if err != nil {
				return err
			}
			if v != actual {
				return ErrReconcile
			}
			return s.confirmBoot(final, artifact.ID, actual, plan.Runtime.Generation)
		})
	}
	if e != nil {
		return failure(e)
	}
	j.CandidateID = plan.Snapshot.Version
	j.State = domain.Restored
	j.ReceiptPending = false
	j.Version = actual
	j.ArtifactID = artifact.ID
	if e = s.journal.Save(ctx, *j); e != nil {
		return ObservedState{actual, string(j.State)}, e
	}
	return ObservedState{actual, string(j.State)}, nil
}
func (s *Supervisor) Recover(ctx context.Context) (ObservedState, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	unlock, e := s.artifacts.Lock(ctx)
	if e != nil {
		return ObservedState{}, e
	}
	defer unlock()
	j, e := s.journal.Load(ctx)
	if e != nil {
		return ObservedState{}, e
	}
	actual, observeErr := s.process.Observe(ctx)
	confirmed, e := s.authority.Confirmed(ctx, j)
	if e != nil {
		return ObservedState{actual, string(j.State)}, e
	}
	if confirmed && observeErr == nil && actual == j.Version {
		j.ReceiptPending = false
		j.State = domain.Succeeded
		return ObservedState{actual, string(j.State)}, s.journal.Save(ctx, j)
	}
	// A cached directory alone is never permission to resurrect security material.
	// Restore resolves current security against the last DB-verified logical config.
	return s.restore(ctx, &j)
}
func (s *Supervisor) RotateLogs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	unlock, e := s.artifacts.Lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	return s.process.RotateLogs(ctx)
}
func (s *Supervisor) Stop(ctx context.Context) error { return s.process.Stop(ctx) }

// ApplyDerived is internal-only and always derives CURRENT VERIFIED logical
// configuration. It accepts no public Actor or draft/candidate payload.
func (s *Supervisor) ApplyDerived(ctx context.Context, kind string) (ObservedState, error) {
	if !domain.DerivedKind(kind) {
		return ObservedState{}, domain.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	unlock, e := s.artifacts.Lock(ctx)
	if e != nil {
		return ObservedState{}, e
	}
	defer unlock()
	j, e := s.journal.Load(ctx)
	if e != nil {
		return ObservedState{}, e
	}
	if j.ReceiptPending {
		return ObservedState{}, ErrReconcile
	}
	return s.restore(ctx, &j)
}
