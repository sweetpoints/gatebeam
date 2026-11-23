package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/application/nodes"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
)

// ReconcileLocal projects an already confirmed native fact. It never reads a
// draft or turns the previous database receipt into an instruction to roll back.
// The caller owns and observes the actual child; no HTTP body can supply this.
func (e *Execution) ReconcileLocal(ctx context.Context, b edge.BootBundle, actual string) error {
	if !e.node.Valid() || b.Manifest.Node != e.node || actual != b.Manifest.Version {
		return edge.ErrReconcile
	}
	source := b.Plan
	if b.SourcePlan != nil {
		source = *b.SourcePlan
	}
	if !((domain.NodeRef{ID: source.Snapshot.Version, Epoch: 1}).Valid()) {
		// The operator-authorized minimum management/default-deny boot has no release
		// row and is never claimed as a successful business publication.
		return nil
	}
	return e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		owner, ok := e.coordinator.ingress.(verifiedIngress)
		if !ok {
			return domain.ErrUnavailable
		}
		if err := owner.GuardPublicationWithin(sc); err != nil {
			return err
		}
		if err := e.nodeGuard(sc); err != nil {
			return err
		}
		current, currentErr := e.coordinator.nodes.CurrentWithin(sc, e.node)
		if currentErr == nil && current.ArtifactID == b.Manifest.ArtifactID && current.Generation == b.Manifest.Generation && current.ReleaseID == source.Snapshot.Version {
			return nil
		}
		if currentErr != nil && !errors.Is(currentErr, domain.ErrNotFound) {
			return currentErr
		}
		if currentErr == nil && current.ObservedAt.After(b.VerifiedAt) {
			return domain.ErrConflict
		}
		candidate, err := e.coordinator.releases.ReadWithin(sc, source.Snapshot.Version)
		if err != nil {
			return err
		}
		expected := candidate.Snapshot
		expected.Version = candidate.ID
		left, _ := json.Marshal(expected)
		right, _ := json.Marshal(source.Snapshot)
		if !bytes.Equal(left, right) || b.Manifest.AuthorizationID != candidate.ID {
			return ErrDenied
		}
		artifact, err := e.compiler.Compile(b.Plan.Snapshot, b.Plan.Runtime)
		if err != nil || artifact.ID != b.Manifest.ArtifactID {
			return edge.ErrReconcile
		}
		state := "restricted"
		fresh, freshErr := e.plan(sc, candidate)
		if freshErr == nil && b.SourcePlan == nil {
			if freshArtifact, err := e.sameArtifact(b.Plan, fresh); err == nil && freshArtifact.ID == artifact.ID {
				state = "succeeded"
			}
		}
		event := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s/%d/%s/%s/%s", e.node.ID, e.node.Epoch, candidate.ID, b.Manifest.ArtifactID, b.VerifiedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")))).String()
		observation := nodes.Observation{EventID: event, Node: e.node, ReleaseID: candidate.ID, ArtifactID: artifact.ID, Generation: b.Manifest.Generation, ImageDigest: e.imageDigest, ObservedAt: b.VerifiedAt, State: state, Bindings: verifiedBindings(b.Plan, artifact)}
		if err = e.coordinator.nodes.ReportWithin(sc, observation); err != nil {
			return err
		}
		if state == "succeeded" {
			return e.maybeFinalizeNodeRelease(sc, owner, fresh, artifact)
		}
		return nil
	})
}
