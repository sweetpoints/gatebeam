package composition

import (
	"context"
	"errors"
	"fmt"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"os"
	"path/filepath"
	"time"
)

func runEdge(ctx context.Context, cfg bootstrap.Config) error {
	if cfg.RuntimeProtocol == 0 {
		return runEdgeControl(ctx, cfg, domain.NodeRef{}, nil, nil, nil)
	}
	node := domain.NodeRef{ID: cfg.NodeID, Epoch: cfg.NodeEpoch}
	if cfg.RuntimeProtocol != 1 || !node.Valid() || cfg.EdgeRoot == "" {
		return errors.New("invalid offline edge identity or runtime root")
	}
	disk, err := filesystem.New(cfg.EdgeRoot)
	if err != nil {
		return err
	}
	logs, err := logfile.OpenNode(filepath.Join(cfg.EdgeRoot, "logs"), node.ID)
	if err != nil {
		return err
	}
	if err = logs.Close(); err != nil {
		return err
	}
	process, err := nginx.NewProcess("/usr/sbin/nginx", cfg.EdgeRoot)
	if err != nil {
		return err
	}
	defer func() {
		stop, cancel := shutdownContext(ctx, 6*time.Second)
		defer cancel()
		_ = process.Stop(stop)
	}()
	bundle, err := disk.LoadConfirmed(ctx, node)
	if err != nil {
		return err
	}
	offline, closeStatus, err := startEdgeStatus(cfg, &bundle.Plan.Runtime)
	if err != nil {
		return err
	}
	defer closeStatus()
	local := edge.NewLocalBoot(process, disk, nginx.BootPolicy{}, time.Now)
	if _, err = local.Start(ctx, node); err != nil {
		return err
	}
	setRoleReady(ctx, lifecycle.Data, true)
	recordManagementApplied(ctx, disk, node)
	controlCtx, cancelControl := context.WithCancel(ctx)
	defer cancelControl()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for controlCtx.Err() == nil {
			_ = runEdgeControl(controlCtx, cfg, node, process, disk, offline)
			timer := time.NewTimer(time.Second)
			select {
			case <-controlCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	rotateBytes, maxBytes, maxFiles := cfg.LogRotateBytes, cfg.LogMaxBytes, cfg.LogMaxFiles
	if rotateBytes == 0 {
		rotateBytes = 64 << 20
	}
	if maxBytes == 0 {
		maxBytes = 1 << 30
	}
	if maxFiles == 0 {
		maxFiles = 2048
	}
	localLogs := edge.LocalLogPolicy{Volume: disk, Process: process, RotateBytes: rotateBytes, MaxBytes: maxBytes, MaxFiles: maxFiles, Now: time.Now}
	var lastLogWarning time.Time
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			cancelControl()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
			}
			return nil
		case <-tick.C:
			// A process/container restart uses exactly the same local path. A control
			// outage never turns into an instruction to stop the data plane.
			needsStart := process.PID() == 0
			confirmed, checkErr := disk.LoadConfirmed(ctx, node)
			if checkErr == nil {
				now := time.Now().UTC()
				if now.Before(confirmed.VerifiedAt) || now.Before(confirmed.CurrentFloor.RecordedAt) {
					checkErr = domain.ErrUnavailable
				} else {
					prepared, e := (nginx.BootPolicy{}).Prepare(ctx, confirmed, now)
					checkErr = e
					if e == nil && prepared.Manifest.ArtifactID != confirmed.Manifest.ArtifactID {
						needsStart = true
					}
				}
			}
			expected := confirmed.Manifest.Version
			if checkErr == nil && needsStart {
				var observed edge.ObservedState
				observed, checkErr = local.Start(ctx, node)
				if checkErr == nil {
					expected = observed.Version
					recordManagementApplied(ctx, disk, node)
				}
			}
			if checkErr == nil {
				actual, e := process.Observe(ctx)
				checkErr = e
				if e == nil && actual != expected {
					checkErr = edge.ErrReconcile
				}
			}
			setRoleReady(ctx, lifecycle.Data, checkErr == nil && process.PID() != 0)
			if roleAccepts(ctx, lifecycle.LocalCleanup) {
				maintenance, stop := context.WithTimeout(ctx, 5*time.Second)
				err := edge.MaintainLocalLogs(maintenance, localLogs)
				stop()
				if err != nil && time.Since(lastLogWarning) >= time.Minute {
					reason := "local_log_maintenance_unavailable"
					if errors.Is(err, edge.ErrLogCapacity) {
						reason = "unarchived_log_capacity"
					}
					fmt.Fprintf(os.Stderr, "{\"component\":\"edge_logs\",\"reason\":\"%s\"}\n", reason)
					lastLogWarning = time.Now()
				}
			}
		}
	}
}
