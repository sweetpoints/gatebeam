package runtime

import (
	"context"
	"gatebeam/internal/modules/deployment/domain"
	"slices"
	"time"
)

func (s *Supervisor) stageBoot(ctx context.Context, plan Plan, artifact Artifact) error {
	if s.boot == nil {
		return nil
	}
	var materials []string
	for _, material := range plan.Runtime.Materials {
		if material.VersionID != "" && !slices.Contains(materials, material.VersionID) {
			materials = append(materials, material.VersionID)
		}
	}
	slices.Sort(materials)
	created := plan.Runtime.Now
	if created.IsZero() {
		created = time.Now().UTC()
	}
	return s.boot.StageConfirmed(ctx, BootBundle{
		Manifest: domain.BootManifest{Format: domain.BootFormat, Node: s.node,
			ArtifactID: artifact.ID, Version: plan.Snapshot.Version + "/" + plan.Runtime.Generation,
			Generation: plan.Runtime.Generation, AuthorizationID: plan.Snapshot.Version,
			CreatedAt: created, MaterialIDs: materials},
		Files: artifact.Files, Plan: plan,
	})
}

func (s *Supervisor) confirmBoot(ctx context.Context, artifactID, version, generation string) error {
	if s.boot == nil {
		return nil
	}
	confirm := func() error {
		return s.boot.Confirm(ctx, BootEvidence{Node: s.node, ArtifactID: artifactID,
			Version: version, Generation: generation, VerifiedAt: time.Now().UTC()})
	}
	if guard, ok := s.authority.(interface {
		ConfirmLocal(context.Context, func() error) error
	}); ok {
		return guard.ConfirmLocal(ctx, confirm)
	}
	return confirm()
}
