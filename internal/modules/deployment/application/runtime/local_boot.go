package runtime

import (
	"context"
	"gatebeam/internal/modules/deployment/domain"
	"maps"
	"reflect"
	"slices"
	"time"
)

// BootPolicy may only retain or restrict the locally confirmed authority. It
// never resolves a draft, obtains a new credential, or contacts a control role.
type BootPolicy interface {
	Prepare(context.Context, BootBundle, time.Time) (BootBundle, error)
}

type LocalBoot struct {
	process Process
	store   BootStore
	policy  BootPolicy
	now     func() time.Time
}

func NewLocalBoot(p Process, store BootStore, policy BootPolicy, now func() time.Time) *LocalBoot {
	return &LocalBoot{process: p, store: store, policy: policy, now: now}
}

func (b *LocalBoot) Start(ctx context.Context, node domain.NodeRef) (ObservedState, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	disk, ok := b.store.(ArtifactStore)
	if !ok || b.policy == nil || b.now == nil || !node.Valid() {
		return ObservedState{}, domain.ErrInvalid
	}
	unlock, err := disk.Lock(ctx)
	if err != nil {
		return ObservedState{}, err
	}
	defer unlock()
	confirmed, err := b.store.LoadConfirmed(ctx, node)
	if err != nil {
		return ObservedState{}, err
	}
	now := b.now().UTC()
	if now.Before(confirmed.VerifiedAt) || now.Before(confirmed.CurrentFloor.RecordedAt) || now.Before(confirmed.Manifest.CreatedAt) || confirmed.CurrentFloor.Sequence == ^uint64(0) {
		return ObservedState{}, domain.ErrUnavailable
	}
	prepared, err := b.policy.Prepare(ctx, confirmed, now)
	if err != nil {
		return ObservedState{}, err
	}
	if prepared.Manifest.Node != node || prepared.Manifest.AuthorizationID != confirmed.Manifest.AuthorizationID {
		return ObservedState{}, domain.ErrInvalid
	}
	floor := confirmed.CurrentFloor
	floor.SecurityBindings = maps.Clone(floor.SecurityBindings)
	floor.RevokedMaterialIDs = slices.Clone(floor.RevokedMaterialIDs)
	floor.Sequence++
	floor.RecordedAt = now
	if err := b.store.RaiseFloor(ctx, floor); err != nil {
		return ObservedState{}, err
	}
	if err = b.store.StageConfirmed(ctx, prepared); err != nil {
		return ObservedState{}, err
	}
	path, err := disk.Stage(ctx, Artifact{ID: prepared.Manifest.ArtifactID, Digest: prepared.Manifest.ArtifactID, Files: prepared.Files})
	if err != nil {
		return ObservedState{}, err
	}
	if err = b.process.Validate(ctx, path); err != nil {
		return ObservedState{}, err
	}
	if err = disk.Switch(ctx, prepared.Manifest.ArtifactID); err != nil {
		return ObservedState{}, err
	}
	if err = b.process.Activate(ctx, prepared.Manifest.Version); err != nil {
		return ObservedState{}, err
	}
	actual, err := b.process.Observe(ctx)
	if err != nil {
		return ObservedState{}, err
	}
	if actual != prepared.Manifest.Version {
		return ObservedState{}, ErrReconcile
	}
	verifiedAt := b.now().UTC()
	if reflect.DeepEqual(prepared.Manifest, confirmed.Manifest) {
		// The existing configuration is already authorized and verified. Save
		// this startup's observation without advancing its security floor again
		// after Nginx can serve traffic. The pre-activation floor remains binding.
		err = b.store.ConfirmKnown(ctx, confirmed.Manifest, floor, verifiedAt)
	} else {
		err = b.store.Confirm(ctx, BootEvidence{Node: node, ArtifactID: prepared.Manifest.ArtifactID, Version: actual, Generation: prepared.Manifest.Generation, VerifiedAt: verifiedAt})
	}
	if err != nil {
		return ObservedState{}, err
	}
	return ObservedState{Version: actual, State: "offline_ready"}, nil
}
