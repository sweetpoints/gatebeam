package publication

import (
	"context"
	"encoding/json"
	"errors"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	ingress "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/transaction"
	"slices"
	"sort"
	"time"
)

// RuntimeSource is the internal current-security binding contract. P5/I5 adapters
// must resolve current generations here; queued bytes never authorize old keys.
type RuntimeSource interface {
	ReadWithin(transaction.Scope, deploy.Snapshot) (edge.RuntimeState, error)
}
type verifiedIngress interface {
	GuardPublicationWithin(transaction.Scope) error
	CommitVerifiedWithin(transaction.Scope, ingress.VerifiedPublication) error
}
type Execution struct {
	node         domain.NodeRef
	imageDigest  string
	confirmScope transaction.Scope
	coordinator  *Coordinator
	jobs         *jobs.Store
	job          jobs.Job
	source       RuntimeSource
	compiler     edge.Compiler
}

func NewExecution(c *Coordinator, j *jobs.Store, lease jobs.Job, source RuntimeSource, compiler edge.Compiler) *Execution {
	return &Execution{coordinator: c, jobs: j, job: lease, source: source, compiler: compiler}
}
func (e *Execution) publisher(id string) (ActorRef, error) {
	var payload struct {
		ReleaseID string   `json:"release_id"`
		Publisher ActorRef `json:"publisher"`
	}
	expectedKind := "deployment.apply"
	if e.node.Valid() {
		expectedKind = "deployment.node.apply.v1"
		if e.job.Target.NodeID != e.node.ID || e.job.Target.Epoch != e.node.Epoch {
			return ActorRef{}, ErrDenied
		}
	}
	if e.job.Kind != expectedKind || json.Unmarshal(e.job.Payload, &payload) != nil || payload.ReleaseID != id {
		return ActorRef{}, ErrDenied
	}
	a := payload.Publisher
	if a.UserID == "" || a.AuthVersion < 1 || a.CredentialID == "" || (a.CredentialKind != "session" && a.CredentialKind != "token") {
		return ActorRef{}, ErrDenied
	}
	return a, nil
}
func (e *Execution) candidate(sc transaction.Scope, a ActorRef, id string) (release.Candidate, error) {
	c := e.coordinator
	v, err := c.releases.ReadWithin(sc, id)
	if err != nil {
		return v, err
	}
	if v.State != domain.Queued {
		return v, domain.ErrConflict
	}
	var source *release.Candidate
	if v.Snapshot.SourceReleaseID != "" {
		old, err := c.releases.ReadWithin(sc, v.Snapshot.SourceReleaseID)
		if err != nil {
			return v, err
		}
		source = &old
	}
	input, err := c.inputsFromSource(sc, a, v.SelectedSiteIDs, v.Expected, source)
	if err != nil {
		return v, err
	}
	digest, err := c.releases.Digest(input)
	if err != nil {
		return v, err
	}
	if digest != v.InputDigest {
		return v, domain.ErrConflict
	}
	if err := e.nodeGuard(sc); err != nil {
		return v, err
	}
	if e.node.Valid() {
		if err := e.coordinator.nodes.RequireDesiredWithin(sc, e.node, id); err != nil {
			return v, err
		}
	}
	return v, nil
}
func (e *Execution) plan(sc transaction.Scope, v release.Candidate) (edge.Plan, error) {
	state, err := e.source.ReadWithin(sc, v.Snapshot)
	if err != nil {
		return edge.Plan{}, err
	}
	snapshot := v.Snapshot
	snapshot.Version = v.ID
	return edge.Plan{Snapshot: snapshot, Runtime: state}, nil
}
func (e *Execution) Prepare(ctx context.Context, id string) (plan edge.Plan, err error) {
	a, err := e.publisher(id)
	if err != nil {
		return plan, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Authenticate, freeze the immutable candidate and fence the lease before
	// permitting private DNS I/O. End this Scope before preparation; then repeat
	// all checks so revocation/publication races cannot authorize the later plan.
	if preparer, ok := e.source.(interface {
		Prepare(context.Context, deploy.Snapshot) error
	}); ok {
		var snapshot deploy.Snapshot
		err = e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
			if err := e.coordinator.identity.GuardWithin(sc, actor(a)); err != nil {
				return err
			}
			v, err := e.candidate(sc, a, id)
			if err != nil {
				return err
			}
			if err = e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
				return err
			}
			snapshot = v.Snapshot
			return nil
		})
		if err != nil {
			return plan, err
		}
		if err = preparer.Prepare(ctx, snapshot); err != nil {
			return plan, err
		}
	}
	err = e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		if err := e.coordinator.identity.GuardWithin(sc, actor(a)); err != nil {
			return err
		}
		v, err := e.candidate(sc, a, id)
		if err != nil {
			return err
		}
		if err = e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
			return err
		}
		plan, err = e.plan(sc, v)
		return err
	})
	return
}
func (e *Execution) ActivateWithin(ctx context.Context, id string, staged edge.Plan, effect func() error) error {
	return e.within(ctx, id, staged, effect, false)
}
func (e *Execution) Within(ctx context.Context, id string, staged edge.Plan, effect func() error) error {
	return e.within(ctx, id, staged, effect, true)
}
func (e *Execution) within(ctx context.Context, id string, staged edge.Plan, effect func() error, finalize bool) error {
	a, err := e.publisher(id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		c := e.coordinator
		if err := c.identity.GuardWithin(sc, actor(a)); err != nil {
			return err
		}
		owner, ok := c.ingress.(verifiedIngress)
		if !ok {
			return domain.ErrUnavailable
		}
		if err := owner.GuardPublicationWithin(sc); err != nil {
			return err
		}
		v, err := e.candidate(sc, a, id)
		if err != nil {
			return err
		}
		fresh, err := e.plan(sc, v)
		if err != nil {
			return err
		}
		artifact, err := e.sameArtifact(staged, fresh)
		if err != nil {
			return err
		}
		if err = e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
			return err
		}
		e.confirmScope = sc
		defer func() { e.confirmScope = nil }()
		if err = effect(); err != nil {
			return err
		}
		if !finalize {
			return nil
		}
		if e.node.Valid() {
			if err = e.recordNodeSuccess(sc, fresh, artifact); err != nil {
				return err
			}
			summary, err := c.nodes.SummaryWithin(sc, id)
			if err != nil {
				return err
			}
			if !summary.Complete {
				return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
			}
		}
		if err = commitOwnerHeads(sc, owner, v); err != nil {
			return err
		}
		if err = c.releases.RecordVerifiedMaterialsWithin(sc, id, artifact.ID, fresh.Snapshot.Version+"/"+fresh.Runtime.Generation, verifiedBindings(fresh, artifact)); err != nil {
			return err
		}
		// Complete uses clock_timestamp, not transaction-start now(): expiry during
		// the bounded native effect rolls back ALL owner heads and DB receipts.
		return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
	})
}
func (e *Execution) sameArtifact(a, b edge.Plan) (edge.Artifact, error) {
	old, err := e.compiler.Compile(a.Snapshot, a.Runtime)
	if err != nil {
		return old, err
	}
	oldRefs := slices.Clone(old.CertificateRefs)
	fresh, err := e.compiler.Compile(b.Snapshot, b.Runtime)
	if err != nil {
		return fresh, err
	}
	if old.Digest != fresh.Digest || !slices.Equal(oldRefs, fresh.CertificateRefs) {
		return fresh, domain.ErrConflict
	}
	fresh.CertificateRefs = slices.Clone(fresh.CertificateRefs)
	return fresh, nil
}
func (e *Execution) current(sc transaction.Scope) (edge.Plan, release.VerifiedReceipt, error) {
	if err := e.nodeGuard(sc); err != nil {
		return edge.Plan{}, release.VerifiedReceipt{}, err
	}
	if e.node.Valid() {
		observation, err := e.coordinator.nodes.CurrentWithin(sc, e.node)
		if err == nil {
			candidate, err := e.coordinator.releases.ReadWithin(sc, observation.ReleaseID)
			if err != nil {
				return edge.Plan{}, release.VerifiedReceipt{}, err
			}
			plan, err := e.plan(sc, candidate)
			return plan, release.VerifiedReceipt{ReleaseID: observation.ReleaseID, ArtifactID: observation.ArtifactID, Version: observation.ReleaseID + "/" + observation.Generation}, err
		}
		if !errors.Is(err, domain.ErrNotFound) {
			return edge.Plan{}, release.VerifiedReceipt{}, err
		}
		// Enrollment catch-up reads the already published logical configuration;
		// a new node still earns its own native proof before getting a receipt.
	}
	v, receipt, err := e.coordinator.releases.CurrentVerifiedWithin(sc)
	if errors.Is(err, domain.ErrNotFound) {
		v = release.Candidate{ID: "bootstrap", Snapshot: deploy.Snapshot{Version: "deployment/v1"}}
	} else if err != nil {
		return edge.Plan{}, receipt, err
	}
	plan, err := e.plan(sc, v)
	return plan, receipt, err
}
func (e *Execution) CurrentVerified(ctx context.Context) (plan edge.Plan, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		owner, ok := e.coordinator.ingress.(verifiedIngress)
		if !ok {
			return domain.ErrUnavailable
		}
		if err := owner.GuardPublicationWithin(sc); err != nil {
			return err
		}
		var err error
		plan, _, err = e.current(sc)
		return err
	})
	return
}
func (e *Execution) RestoreActivateWithin(ctx context.Context, staged edge.Plan, effect func(context.Context) error) error {
	return e.restoreWithin(ctx, staged, effect, false)
}
func (e *Execution) WithRestore(ctx context.Context, staged edge.Plan, effect func(context.Context) error) error {
	return e.restoreWithin(ctx, staged, effect, true)
}
func (e *Execution) restoreWithin(ctx context.Context, staged edge.Plan, effect func(context.Context) error, finalize bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		owner, ok := e.coordinator.ingress.(verifiedIngress)
		if !ok {
			return domain.ErrUnavailable
		}
		if err := owner.GuardPublicationWithin(sc); err != nil {
			return err
		}
		fresh, receipt, err := e.current(sc)
		if err != nil {
			return err
		}
		artifact, err := e.sameArtifact(staged, fresh)
		if err != nil {
			return err
		}
		if e.job.Kind == "deployment.node.generation.v1" && (!e.node.Valid() || e.job.Target.NodeID != e.node.ID || e.job.Target.Epoch != e.node.Epoch) {
			return ErrDenied
		}
		if e.job.Kind == "deployment.generation" || e.job.Kind == "deployment.node.generation.v1" {
			var payload struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(e.job.Payload, &payload) != nil || !domain.DerivedKind(payload.Kind) {
				return domain.ErrInvalid
			}
			if err = e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
				return err
			}
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		e.confirmScope = sc
		defer func() { e.confirmScope = nil }()
		if err = effect(ctx); err != nil {
			return err
		}
		if !finalize {
			return nil
		}
		if e.node.Valid() && receipt.ReleaseID != "" {
			if err = e.recordNodeSuccess(sc, fresh, artifact); err != nil {
				return err
			}
			if err = e.maybeFinalizeNodeRelease(sc, owner, fresh, artifact); err != nil {
				return err
			}
		} else if receipt.ReleaseID != "" {
			if err = e.coordinator.releases.RecordVerifiedMaterialsWithin(sc, receipt.ReleaseID, artifact.ID, fresh.Snapshot.Version+"/"+fresh.Runtime.Generation, verifiedBindings(fresh, artifact)); err != nil {
				return err
			}
		}
		if e.job.Kind == "deployment.generation" || e.job.Kind == "deployment.node.generation.v1" {
			return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
		}
		return nil
	})
}
func (e *Execution) Confirmed(ctx context.Context, j domain.ApplyJournal) (confirmed bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		owner, ok := e.coordinator.ingress.(verifiedIngress)
		if !ok {
			return domain.ErrUnavailable
		}
		if err := owner.GuardPublicationWithin(sc); err != nil {
			return err
		}
		plan, r, err := e.current(sc)
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		artifact, err := e.compiler.Compile(plan.Snapshot, plan.Runtime)
		if err != nil {
			return err
		}
		confirmed = r.ReleaseID == j.CandidateID && r.ArtifactID == j.ArtifactID && r.Version == j.Version && artifact.ID == j.ArtifactID
		return nil
	})
	return
}
func (e *Execution) ReportProgress(ctx context.Context, id, stage, cause string) error {
	if e.node.Valid() {
		return nil
	}
	if _, err := e.publisher(id); err != nil {
		return err
	}
	ctx, c := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer c()
	return e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		if err := e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
			return err
		}
		return e.coordinator.releases.ProgressWithin(sc, id, stage, cause)
	})
}
func (e *Execution) RecordFailure(ctx context.Context, id string, result edge.ApplyResult) error {
	if e.node.Valid() {
		return e.recordNodeFailure(ctx, id, result)
	}
	if _, err := e.publisher(id); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return e.coordinator.tx.Within(ctx, func(sc transaction.Scope) error {
		if err := e.jobs.FenceWithin(sc, e.job.ID, e.job.LeaseToken); err != nil {
			return err
		}
		if result.Cause == "" {
			result.Cause = "unavailable"
		}
		if result.State == "" {
			result.State = "failed"
		}
		if err := e.coordinator.releases.ProgressWithin(sc, id, result.State, result.Cause); err != nil {
			return err
		}
		if err := e.coordinator.releases.RecordOutcomeWithin(sc, id, domain.State(result.State), result.Version, result.RestoredVersion); err != nil {
			return err
		}
		return e.jobs.CompleteWithin(sc, e.job.ID, e.job.LeaseToken)
	})
}

// Only the exact plan that passed final authority and native observation enters
// the owning receipt. Stored/current certificate queries never write this state.
func verifiedBindings(p edge.Plan, artifact edge.Artifact) []release.MaterialBinding {
	out := []release.MaterialBinding{}
	// Both content digest and these refs were checked by sameArtifact. Consume
	// value copies; never retain or mutate the compiler's selection slice.
	for _, ref := range artifact.CertificateRefs {
		m, ok := p.Runtime.Materials[ref.ID]
		if ok && ref.Kind == "certificate" && ref.Revision == m.Revision && m.VersionID != "" {
			out = append(out, release.MaterialBinding{Kind: ref.Kind, ID: ref.ID, Revision: ref.Revision, VersionID: m.VersionID, Digest: m.Digest})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
