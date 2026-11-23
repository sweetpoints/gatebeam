// Package composition owns process assembly; unavailable services fail closed.
package composition

import (
	"context"
	"errors"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"time"
)

var ErrProcessCapability = errors.New("process configuration includes forbidden CA capability")

var ErrNotImplemented = errors.New("mode not implemented")
var ErrUnsupportedMode = errors.New("unsupported mode")

func runProcess(ctx context.Context, mode string, cfg bootstrap.Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !bootstrap.SupportedMode(mode) {
		return ErrUnsupportedMode
	}
	if bootstrap.ValidateCapabilities(mode, cfg) != nil {
		return ErrProcessCapability
	}
	if mode == "backup-export" {
		return exportBackup(ctx, cfg)
	}
	if mode == "backup-restore" {
		return restoreBackup(ctx, cfg)
	}
	if cfg.BackupRecipient != "" && (mode == "api" || mode == "worker" || (mode == "edge" && cfg.RuntimeProtocol == 0) || mode == "ca") {
		if e := ExportBackupCapsule(ctx, cfg); e != nil {
			return e
		}
	}
	if mode == "query" {
		return runQuery(ctx, cfg)
	}
	if mode == "ca" {
		return runCA(ctx, cfg)
	}
	if mode == "ca-import" {
		return importCA(ctx, cfg)
	}
	if mode == "ca-bootstrap" {
		return bootstrapCA(ctx, cfg)
	}
	if mode == "edge" {
		return runEdge(ctx, cfg)
	}
	if mode == "worker" {
		return runWorker(ctx, cfg)
	}
	if mode == "api" {
		return runAPI(ctx, cfg)
	}
	if mode == "bootstrap" {
		return ErrBootstrapDisplay
	}
	if mode == "migrate" {
		c, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		p, e := postgres.Open(c, cfg)
		if e != nil {
			return e
		}
		defer p.Close()
		if e = postgres.Migrate(c, p); e != nil {
			return e
		}
		if cfg.MigrateRoles {
			return postgres.MigrateRoles(c, p)
		}
		return nil
	}
	return ErrNotImplemented
}
