package composition

import (
	"context"
	"errors"
	"fmt"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"path/filepath"
	"time"
)

// InitializeEdge is an explicit online operator action. Ordinary startup always
// requires a confirmed local bundle and cannot enter this initialization path.
func InitializeEdge(ctx context.Context, c bootstrap.Config) error {
	node := domain.NodeRef{ID: c.NodeID, Epoch: c.NodeEpoch}
	if c.Mode != "edge" || c.RuntimeProtocol != 1 || !node.Valid() || bootstrap.ValidateCapabilities("edge", c) != nil {
		return errors.New("controlled edge initialization configuration denied")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if _, e := os.Lstat(filepath.Join(c.EdgeRoot, "boot", "confirmed.json")); !os.IsNotExist(e) {
		return errors.New("existing boot evidence requires normal restart")
	}
	disk, e := filesystem.New(c.EdgeRoot)
	if e != nil {
		return e
	}
	offline, closeStatus, e := startEdgeStatus(c, nil)
	if e != nil {
		return e
	}
	defer closeStatus()
	return runEdgeControlMode(ctx, c, node, nil, disk, offline, true, nil)
}

type initializationBoot struct{ edge.BootStore }

func (b initializationBoot) StageConfirmed(ctx context.Context, bundle edge.BootBundle) error {
	if e := b.BootStore.StageConfirmed(ctx, bundle); e != nil {
		return fmt.Errorf("initialize_local_bundle_stage: %w", e)
	}
	return nil
}
func (b initializationBoot) Confirm(ctx context.Context, evidence edge.BootEvidence) error {
	if e := b.BootStore.Confirm(ctx, evidence); e != nil {
		return fmt.Errorf("initialize_local_bundle_confirm: %w", e)
	}
	return nil
}

// PreviewEdgeInitialization returns a reference for controlled registration.
// It compiles an empty management baseline on a fresh installation, or reads
// the existing globally verified artifact. It does not activate native traffic.
func PreviewEdgeInitialization(ctx context.Context, c bootstrap.Config) (string, error) {
	node := domain.NodeRef{ID: c.NodeID, Epoch: c.NodeEpoch}
	if c.Mode != "edge" || c.RuntimeProtocol != 1 || !node.Valid() || bootstrap.ValidateCapabilities("edge", c) != nil {
		return "", ErrProcessCapability
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var id string
	e := runEdgeControlMode(ctx, c, node, nil, nil, nil, false, &id)
	return id, e
}
