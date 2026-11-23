package publication

import (
	"context"
	"errors"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	ingress "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/platform/transaction"
	"time"
)

func (e *Execution) SetNode(node domain.NodeRef, image string) { e.node = node; e.imageDigest = image }
func (e *Execution) nodeGuard(sc transaction.Scope) error {
	if e.node.Valid() {
		if e.coordinator.nodes == nil {
			return domain.ErrUnavailable
		}
		return e.coordinator.nodes.AuthorizeRuntimeWithin(sc, e.node, e.imageDigest)
	}
	if e.coordinator.nodes != nil {
		targets, err := e.coordinator.nodes.TargetsWithin(sc)
		if err != nil {
			return err
		}
		if len(targets) > 0 {
			return nodes.ErrIdentity
		}
	}
	return nil
}

// ConfirmLocal runs synchronously inside the original authority transaction.
// Recheck the DB clock lease after native verification and before persisting a
// local authority that may outlive a lost commit acknowledgement.
func (e *Execution) ConfirmLocal(ctx context.Context, confirm func() error) error {
	if e.confirmScope == nil || ctx.Err() != nil || e.confirmScope.Context().Err() != nil {
		return domain.ErrConflict
	}
	if err := e.nodeGuard(e.confirmScope); err != nil {
		return err
	}
	if e.job.ID != "" {
		if err := e.jobs.FenceWithin(e.confirmScope, e.job.ID, e.job.LeaseToken); err != nil {
			return err
		}
	}
	return confirm()
}
func (e *Execution) recordNodeSuccess(sc transaction.Scope, plan edge.Plan, artifact edge.Artifact) error {
	eventID := e.job.ID
	if eventID == "" {
		var err error
		eventID, err = e.coordinator.ids.NewID()
		if err != nil {
			return err
		}
	}
	return e.coordinator.nodes.ReportWithin(sc, nodes.Observation{EventID: eventID, Node: e.node, ReleaseID: plan.Snapshot.Version, ArtifactID: artifact.ID, Generation: plan.Runtime.Generation, ImageDigest: e.imageDigest, ObservedAt: time.Now().UTC(), State: "succeeded", Bindings: verifiedBindings(plan, artifact)})
}
func (e *Execution) maybeFinalizeNodeRelease(sc transaction.Scope, owner verifiedIngress, plan edge.Plan, artifact edge.Artifact) error {
	c := e.coordinator
	if err := c.nodes.RequireDesiredWithin(sc, e.node, plan.Snapshot.Version); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil
		}
		return err
	}
	summary, err := c.nodes.SummaryWithin(sc, plan.Snapshot.Version)
	if err != nil || !summary.Complete {
		return err
	}
	candidate, err := c.releases.ReadWithin(sc, plan.Snapshot.Version)
	if err != nil {
		return err
	}
	if candidate.State == domain.Succeeded {
		return nil
	}
	if err = commitOwnerHeads(sc, owner, candidate); err != nil {
		return err
	}
	return c.releases.RecordVerifiedMaterialsWithin(sc, candidate.ID, artifact.ID, plan.Snapshot.Version+"/"+plan.Runtime.Generation, verifiedBindings(plan, artifact))
}
func (e *Execution) recordNodeFailure(ctx context.Context, id string, result edge.ApplyResult) error {
	if result.State == "receipt_pending" {
		return nil
	}
	if _, err := e.publisher(id); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		if err := e.nodeGuard(sc); err != nil {
			return err
		}
		if err := e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
			return err
		}
		if err := e.coordinator.nodes.RequireDesiredWithin(sc, e.node, id); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
			}
			return err
		}
		current, err := e.coordinator.nodes.CurrentWithin(sc, e.node)
		if err == nil && current.ReleaseID == id && current.State == "succeeded" && result.Version == id+"/"+current.Generation {
			return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
		}
		state := result.State
		if state != "failed" && state != "restored" && state != "restore_failed" {
			state = "failed"
		}
		if err = e.coordinator.nodes.ReportWithin(sc, nodes.Observation{EventID: e.job.ID, Node: e.node, ReleaseID: id, ImageDigest: e.imageDigest, ObservedAt: time.Now().UTC(), State: state}); err != nil {
			return err
		}
		return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
	})
}
func commitOwnerHeads(sc transaction.Scope, owner verifiedIngress, v release.Candidate) error {
	var err error
	cmd := ingress.VerifiedPublication{PublishedBase: v.PublishedBase}
	for _, change := range v.Changes {
		switch change.Kind {
		case "site":
			for _, s := range v.Snapshot.Sites {
				if s.ID == change.ID {
					out := ingress.VerifiedSite{ID: s.ID, Revision: s.Revision}
					if err = mapValue(s.Config, &out.Config); err != nil {
						return err
					}
					cmd.Sites = append(cmd.Sites, out)
				}
			}
		case "target":
			for _, t := range v.Snapshot.Targets {
				if t.ID == change.ID {
					out := ingress.VerifiedTarget{ID: t.ID, Revision: t.Revision}
					if err = mapValue(t.Config, &out.Config); err != nil {
						return err
					}
					cmd.Targets = append(cmd.Targets, out)
				}
			}
		}
	}
	if err = owner.CommitVerifiedWithin(sc, cmd); err != nil {
		return err
	}
	return nil
}
