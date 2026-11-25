package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"strings"
	"time"
)

func IntentDigest(s upgrade.Step) string {
	raw, _ := json.Marshal(s)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type ImageApprover interface {
	ApproveUpgradeImages(context.Context, upgrade.Step) error
	VerifyUpgradeImages(context.Context, upgrade.Step) error
}

// OperationObservationTimeout bounds observing an asynchronous upgrade operation.
const OperationObservationTimeout = 6 * time.Minute

type MembershipRetirement interface {
	RetireNode(context.Context, upgrade.Step) error
	VerifyRetiredNode(context.Context, upgrade.Step) error
}

type Adapter struct {
	Retirement         MembershipRetirement
	Plan               upgrade.Plan
	Cloud              Cloud
	Host               SSHHost
	Approver           ImageApprover
	CheckCompatibility func(context.Context) error
}

func (a *Adapter) step(id string) (upgrade.Step, error) {
	for _, s := range a.Plan.Steps {
		if s.ID == id {
			return s, nil
		}
	}
	for _, n := range a.Plan.Inventory.Nodes {
		steps, e := upgrade.Compensation(a.Plan, n.Node.ID)
		if e == nil {
			for _, s := range steps {
				if s.ID == id {
					return s, nil
				}
			}
		}
	}
	for _, blocked := range a.Plan.Steps {
		steps, err := upgrade.DrainRestoration(a.Plan, blocked.ID)
		if err != nil {
			continue
		}
		for _, step := range steps {
			if step.ID == id {
				return step, nil
			}
		}
	}
	return upgrade.Step{}, ErrOperation
}
func (a *Adapter) node(s upgrade.Step) (domain.NodeDeployment, error) {
	for _, n := range s.Targets {
		if n.Node == s.Node {
			return n, nil
		}
	}
	return domain.NodeDeployment{}, ErrOperation
}
func (a *Adapter) Observe(ctx context.Context, id string) (upgrade.NodeState, error) {
	for _, n := range a.Plan.Inventory.Nodes {
		if n.Node.ID == id {
			return a.Host.Observe(ctx, n)
		}
	}
	return upgrade.NodeState{}, ErrOperation
}

// checkRemainingCapacity counts only healthy survivors that are still serving
// in both entry backends with their observed image set.
func (a *Adapter) checkRemainingCapacity(ctx context.Context, s upgrade.Step) error {
	survivors := make(map[domain.NodeRef]map[string]string, len(s.Targets))
	healthy := make([]domain.NodeDeployment, 0, len(s.Targets))
	for _, other := range s.Targets {
		if other.Node == s.Node {
			continue
		}
		state, err := a.Host.Observe(ctx, other)
		if err != nil || !state.Ready || !state.ControlReady ||
			a.Cloud.BackendHealthy(ctx, other, false) != nil || a.Cloud.BackendHealthy(ctx, other, true) != nil {
			continue
		}
		survivors[other.Node] = state.Images
		healthy = append(healthy, other)
	}
	if !upgrade.QualifiesRemainingCapacity(s.Capacity, survivors) {
		return upgrade.ErrCapacity
	}
	return a.Cloud.CheckCapacity(ctx, healthy, s.Capacity)
}

// CheckBeforeStep runs before persisting an in-flight operation. A failed
// read-only check leaves a paused step with no uncertain write to reconcile.
func (a *Adapter) CheckBeforeStep(ctx context.Context, s upgrade.Step) error {
	switch s.Kind {
	case "update", "approve-images":
		for _, planned := range a.Plan.Steps {
			if planned.ID == s.ID {
				return a.checkRemainingCapacity(ctx, s)
			}
		}
		return nil // Compensation restores the target, even after evidence expiry.
	case "management-remove", "public-remove", "private-remove", "drain", "host-stop", "retire-membership":
		if s.Kind == "management-remove" && a.Cloud.CheckInventory(ctx, s.Targets) != nil {
			return ErrOperation
		}
		if s.Kind == "retire-membership" {
			target, err := a.node(s)
			if err != nil || a.Cloud.VerifyMembership(ctx, target, false, false) != nil || a.Cloud.VerifyMembership(ctx, target, true, false) != nil {
				return ErrOperation
			}
		}
		return a.checkRemainingCapacity(ctx, s)
	default:
		return nil
	}
}

func (a *Adapter) Apply(ctx context.Context, s upgrade.Step) (upgrade.OperationRef, error) {
	expected, e := a.step(s.ID)
	if e != nil || IntentDigest(expected) != IntentDigest(s) {
		return upgrade.OperationRef{}, ErrOperation
	}
	n, e := a.node(s)
	if e != nil {
		return upgrade.OperationRef{}, e
	}
	switch s.Kind {
	case "precheck":
		if e := a.Cloud.CheckCapacity(ctx, s.Targets, s.Capacity); e != nil {
			return upgrade.OperationRef{}, e
		}
		if a.Cloud.CheckInventory(ctx, s.Targets) != nil {
			return upgrade.OperationRef{}, ErrOperation
		}
		for _, n := range s.Targets {
			if a.Cloud.BackendHealthy(ctx, n, false) != nil || a.Cloud.BackendHealthy(ctx, n, true) != nil {
				return upgrade.OperationRef{}, ErrOperation
			}
		}
		return a.Host.Start(ctx, s)
	case "public-remove", "public-add", "private-remove", "private-add", "host-stop", "host-start":
		return a.Cloud.Mutate(ctx, s, n)
	case "compatibility":
		if a.CheckCompatibility == nil || a.CheckCompatibility(ctx) != nil {
			return upgrade.OperationRef{}, ErrOperation
		}
		return upgrade.OperationRef{StepID: s.ID, HostCommandID: s.ID}, nil
	case "retire-membership":
		if a.Retirement == nil {
			return upgrade.OperationRef{}, ErrOperation
		}
		if err := a.Retirement.RetireNode(ctx, s); err != nil {
			return upgrade.OperationRef{}, err
		}
		return upgrade.OperationRef{StepID: s.ID, HostCommandID: s.ID}, nil
	case "approve-images":
		if a.Approver == nil || a.Approver.ApproveUpgradeImages(ctx, s) != nil {
			return upgrade.OperationRef{}, ErrOperation
		}
		return upgrade.OperationRef{StepID: s.ID, HostCommandID: s.ID}, nil
	default:
		return a.Host.Start(ctx, s)
	}
}
func (a *Adapter) Wait(ctx context.Context, op upgrade.OperationRef) error {
	s, e := a.step(op.StepID)
	if e != nil {
		return e
	}
	n, e := a.node(s)
	if e != nil {
		return e
	}
	if s.Kind == "compatibility" {
		if a.CheckCompatibility == nil {
			return ErrOperation
		}
		return a.CheckCompatibility(ctx)
	}
	if s.Kind == "approve-images" {
		if a.Approver == nil {
			return ErrOperation
		}
		return a.Approver.VerifyUpgradeImages(ctx, s)
	}
	if s.Kind == "retire-membership" {
		if a.Retirement == nil || op.HostCommandID != s.ID || op.CloudOperation != "" {
			return ErrOperation
		}
		return a.Retirement.VerifyRetiredNode(ctx, s)
	}
	ctx, cancel := context.WithTimeout(ctx, OperationObservationTimeout)
	defer cancel()
	for {
		if op.CloudOperation != "" {
			e = a.Cloud.VerifyOperation(ctx, op)
			if e == nil {
				var result struct{ TargetLink string }
				if a.Cloud.request(ctx, "GET", op.CloudOperation, nil, &result) != nil {
					return ErrOperation
				}
				target := n.PublicBackend
				if strings.HasPrefix(s.Kind, "private-") {
					target = n.PrivateBackend
				}
				if strings.HasPrefix(s.Kind, "host-") {
					target = n.Instance
				}
				if resourcePath(result.TargetLink) != target {
					return ErrOperation
				}
				switch s.Kind {
				case "public-remove", "public-add", "private-remove", "private-add":
					e = a.Cloud.VerifyMembership(ctx, n, strings.HasPrefix(s.Kind, "private-"), strings.HasSuffix(s.Kind, "-add"))
					if e == nil && strings.HasSuffix(s.Kind, "-add") {
						e = a.Cloud.BackendHealthy(ctx, n, strings.HasPrefix(s.Kind, "private-"))
					}
				case "host-stop":
					e = a.Cloud.InstanceStopped(ctx, n.Instance)
				}
			}
		} else if op.HostCommandID == s.ID {
			e = a.Host.Completed(ctx, s)
		} else {
			return ErrOperation
		}
		if e == nil {
			return nil
		}
		if errors.Is(e, upgrade.ErrFailed) || errors.Is(e, upgrade.ErrPaused) {
			return e
		}
		select {
		case <-ctx.Done():
			return ErrOperation
		case <-time.After(time.Second):
		}
	}
}
func (a *Adapter) VerifyRecovery(ctx context.Context, p upgrade.RecoveryProof) error {
	if p.BatchID != a.Plan.ID || p.PreviousExecutor == "" {
		return ErrOperation
	}
	for _, n := range a.Plan.Inventory.Nodes {
		if n.Instance == p.PreviousExecutor {
			return ErrOperation
		}
	}
	if a.Cloud.InstanceStopped(ctx, p.PreviousExecutor) != nil {
		return ErrOperation
	}
	for _, op := range p.Operations {
		if e := a.Wait(ctx, op); e != nil {
			return e
		}
	}
	return nil
}
