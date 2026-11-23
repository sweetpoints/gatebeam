package runtime

import (
	"context"
	"gatebeam/internal/modules/deployment/domain"
	"time"
)

type BootBundle struct {
	Manifest     domain.BootManifest
	Files        map[string][]byte
	Plan         Plan
	SourcePlan   *Plan
	CurrentFloor domain.SecurityFloor
	VerifiedAt   time.Time
}

type BootEvidence struct {
	Node                            domain.NodeRef
	ArtifactID, Version, Generation string
	MetadataDigest                  string
	VerifiedAt                      time.Time
}

type BootStore interface {
	LoadConfirmed(context.Context, domain.NodeRef) (BootBundle, error)
	StageConfirmed(context.Context, BootBundle) error
	Confirm(context.Context, BootEvidence) error
	ConfirmKnown(context.Context, domain.BootManifest, domain.SecurityFloor, time.Time) error
	RaiseFloor(context.Context, domain.SecurityFloor) error
}
