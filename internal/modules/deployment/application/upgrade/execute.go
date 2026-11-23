package upgrade

import (
	"context"
	"errors"
	"reflect"
)

type Executor struct {
	Store            Store
	Operations       Operations
	ExecutorInstance string
}

func (x *Executor) Run(ctx context.Context, p Plan) error {
	if x.Store == nil || x.Operations == nil || x.ExecutorInstance == "" || p.ExecutorInstance != x.ExecutorInstance {
		return ErrInvalid
	}
	canonical, e := BuildPlan(p.Request, p.Inventory)
	if e != nil || !reflect.DeepEqual(canonical, p) {
		return ErrInvalid
	}
	r := Run{Plan: p, Owner: x.ExecutorInstance, Revision: 1, State: "running"}
	if e := x.Store.Create(ctx, r); e != nil {
		return e
	}
	return x.execute(ctx, r)
}
func (x *Executor) save(ctx context.Context, r *Run) error {
	old := r.Revision
	r.Revision++
	return x.Store.Save(ctx, *r, old)
}
func (x *Executor) pause(ctx context.Context, r *Run, cause error) error {
	r.State = "paused"
	return errors.Join(ErrPaused, cause, x.save(ctx, r))
}
func (x *Executor) execute(ctx context.Context, r Run) error {
	steps := r.Plan.Steps
	if len(r.RecoverySteps) > 0 {
		steps = r.RecoverySteps
	}
	for r.Next < len(steps) {
		s := steps[r.Next]
		// Inspect both roles and dependency health before each destructive action;
		// failure pauses the batch, never prevents independent offline data startup.
		if s.Kind == "precheck" || s.Kind == "management-remove" {
			for _, n := range s.Targets {
				state, e := x.Operations.Observe(ctx, n.Node.ID)
				if e != nil || !state.Ready || !state.ControlReady {
					return x.pause(ctx, &r, errors.Join(ErrInvalid, e))
				}
			}
		}
		r.Pending = &s
		r.Operation = nil
		if e := x.save(ctx, &r); e != nil {
			return errors.Join(ErrPaused, e)
		}
		op, e := x.Operations.Apply(ctx, s)
		if e != nil {
			return x.pause(ctx, &r, e)
		}
		if op.StepID != s.ID || op.CloudOperation == "" && op.HostCommandID == "" {
			return x.pause(ctx, &r, ErrInvalid)
		}
		r.Operation = &op
		if e = x.save(ctx, &r); e != nil {
			return errors.Join(ErrPaused, e)
		}
		if e = x.Operations.Wait(ctx, op); e != nil {
			if errors.Is(e, ErrFailed) && s.Kind == "verify-api" && len(r.RecoverySteps) == 0 {
				return x.compensate(ctx, r, s.Node.ID)
			}
			return x.pause(ctx, &r, e)
		}
		r.Next++
		r.Pending = nil
		r.Operation = nil
		if e = x.save(ctx, &r); e != nil {
			return errors.Join(ErrPaused, e)
		}
	}
	r.State = "completed"
	if len(r.RecoverySteps) > 0 {
		r.State = "rolled_back"
	}
	e := x.save(ctx, &r)
	if e == nil && r.State == "rolled_back" {
		return ErrRolledBack
	}
	return e
}
func (x *Executor) Resume(ctx context.Context, id string, proof RecoveryProof) error {
	if x.Store == nil || x.Operations == nil || x.ExecutorInstance == "" {
		return ErrInvalid
	}
	r, e := x.Store.Load(ctx, id)
	if e != nil {
		return e
	}
	canonical, e := BuildPlan(r.Plan.Request, r.Plan.Inventory)
	if e != nil || !reflect.DeepEqual(canonical, r.Plan) {
		return ErrInvalid
	}
	if (r.State != "paused" && r.State != "running") || r.Owner == x.ExecutorInstance || proof.PreviousExecutor != r.Owner || proof.Revision != r.Revision || proof.BatchID != id {
		return ErrConflict
	}
	if r.Pending == nil && len(proof.Operations) != 0 || r.Pending != nil && len(proof.Operations) != 1 {
		return ErrInvalid
	}
	if r.Pending != nil {
		op := proof.Operations[0]
		if op.StepID != r.Pending.ID || op.HostCommandID == "" && op.CloudOperation == "" || r.Operation != nil && !reflect.DeepEqual(*r.Operation, op) {
			return ErrInvalid
		}
	}
	if len(r.RecoverySteps) > 0 {
		expected, e := Compensation(r.Plan, r.RecoveryNode)
		if e != nil || !reflect.DeepEqual(expected, r.RecoverySteps) {
			return ErrInvalid
		}
	}
	// The adapter verifies the old execution VM is TERMINATED and all referenced
	// provider/host operations have actually completed. No time-based takeover.
	if e = x.Operations.VerifyRecovery(ctx, proof); e != nil {
		if errors.Is(e, ErrFailed) && r.Pending != nil && r.Pending.Kind == "verify-api" && len(r.RecoverySteps) == 0 {
			r.Owner = x.ExecutorInstance
			r.State = "running"
			if saveErr := x.save(ctx, &r); saveErr != nil {
				return saveErr
			}
			return x.compensate(ctx, r, r.Pending.Node.ID)
		}
		return errors.Join(ErrPaused, e)
	}
	if r.Pending != nil {
		if e = x.Operations.Wait(ctx, proof.Operations[0]); e != nil {
			return errors.Join(ErrPaused, e)
		}
		r.Next++
		r.Pending = nil
		r.Operation = nil
	}
	r.Owner = x.ExecutorInstance
	r.State = "running"
	if e = x.save(ctx, &r); e != nil {
		return e
	}
	return x.execute(ctx, r)
}

func (x *Executor) compensate(ctx context.Context, r Run, node string) error {
	for _, n := range r.Plan.Inventory.Nodes {
		if n.Node.ID != node {
			state, e := x.Operations.Observe(ctx, n.Node.ID)
			if e != nil || !state.Ready || !state.ControlReady {
				return x.pause(ctx, &r, ErrFailed)
			}
		}
	}
	steps, e := Compensation(r.Plan, node)
	if e != nil {
		return x.pause(ctx, &r, e)
	}
	r.RecoverySteps = steps
	r.RecoveryNode = node
	r.Next = 0
	r.Pending = nil
	r.Operation = nil
	r.State = "running"
	if e = x.save(ctx, &r); e != nil {
		return errors.Join(ErrPaused, e)
	}
	return x.execute(ctx, r)
}
