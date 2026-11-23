package composition

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/operations"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type DeploymentIntent struct {
	CapacityReportFile string            `json:"capacity_report_file,omitempty"`
	Request            upgrade.Request   `json:"request"`
	Inventory          upgrade.Inventory `json:"inventory"`
}

func PlanDeployment(path string) (upgrade.Plan, error) {
	var v DeploymentIntent
	if e := input(path, &v); e != nil {
		return upgrade.Plan{}, e
	}
	if v.CapacityReportFile != "" {
		var report domain.CapacityEvidence
		if e := input(v.CapacityReportFile, &report); e != nil {
			return upgrade.Plan{}, e
		}
		report.Digest = ""
		raw, _ := json.Marshal(report)
		sum := sha256.Sum256(raw)
		report.Digest = hex.EncodeToString(sum[:])
		v.Inventory.Capacity = &report
	}
	return upgrade.BuildPlan(v.Request, v.Inventory)
}

// ExecuteDeployment is deliberately separate from PlanDeployment: the dry-run
// call graph never constructs adapters, loads a DB secret or opens a journal.
func ExecuteDeployment(ctx context.Context, plan upgrade.Plan, config, executor, resume string, proof upgrade.RecoveryProof) error {
	if !domain.ValidInstanceReference(executor) {
		return upgrade.ErrInvalid
	}
	if resume == "" {
		if e := deploymentCapacity(plan); e != nil {
			return e
		}
	}
	c, e := bootstrap.Load(config)
	if e != nil || c.Mode != "migrate" {
		return errors.New("dedicated deployment DB configuration required")
	}
	p, e := postgres.Open(ctx, c)
	if e != nil {
		return e
	}
	defer p.Close()
	store := repo.UpgradeStore{Pool: p}
	if resume != "" {
		r, e := store.Load(ctx, resume)
		if e != nil {
			return e
		}
		plan = r.Plan
		if e = deploymentCapacity(plan); e != nil {
			return e
		}
	}
	check := func(ctx context.Context) error {
		var schema, roles int64
		e := p.QueryRow(ctx, `SELECT (SELECT max(version_id) FROM goose_db_version WHERE is_applied),(SELECT max(version_id) FROM gatebeam_role_version WHERE is_applied)`).Scan(&schema, &roles)
		if e != nil || schema != 27 || roles != 6 {
			return upgrade.ErrInvalid
		}
		return nil
	}
	if e = check(ctx); e != nil {
		return e
	}
	adapter := &operations.Adapter{Plan: plan, Cloud: operations.Cloud{Token: operations.GcloudToken}, Host: operations.SSHHost{}, Approver: store, CheckCompatibility: check}
	x := upgrade.Executor{Store: store, Operations: adapter, ExecutorInstance: executor}
	if resume != "" {
		return x.Resume(ctx, resume, proof)
	}
	return x.Run(ctx, plan)
}
func ReadDeploymentProof(path string) (upgrade.RecoveryProof, error) {
	var p upgrade.RecoveryProof
	e := input(path, &p)
	return p, e
}
func RunDeploymentHost(ctx context.Context, mode, value string) (any, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("controlled gateway host identity required")
	}
	st, e := os.Lstat("/etc/gatebeam/host.json")
	if e != nil || !st.Mode().IsRegular() {
		return nil, upgrade.ErrInvalid
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	resolved, e := filepath.EvalSymlinks("/etc/gatebeam")
	if !ok || owner.Uid != 0 || e != nil || resolved != "/etc/gatebeam" {
		return nil, upgrade.ErrInvalid
	}
	var c operations.HostConfiguration
	if e := input("/etc/gatebeam/host.json", &c); e != nil {
		return nil, e
	}
	if c.Node.Validate() != nil {
		return nil, upgrade.ErrInvalid
	}
	j := operations.HostJournal{Directory: "/var/lib/gatebeam-upgrades"}
	h := operations.LocalHost{Configuration: c, ConfigurationFile: "/etc/gatebeam/host.json", Journal: j.Directory}
	switch mode {
	case "status":
		if value != c.Node.Node.ID {
			return nil, upgrade.ErrInvalid
		}
		return h.Status(ctx)
	case "receipt":
		return j.Receipt(value)
	case "dispatch":
		raw, e := base64.RawURLEncoding.DecodeString(value)
		if e != nil || len(raw) > 256<<10 {
			return nil, upgrade.ErrInvalid
		}
		var s upgrade.Step
		if json.Unmarshal(raw, &s) != nil {
			return nil, upgrade.ErrInvalid
		}
		if e = j.Dispatch(ctx, s); e != nil {
			return nil, e
		}
		return map[string]bool{"Accepted": true}, nil
	case "execute":
		ctx, cancel := context.WithTimeout(ctx, 9*time.Minute)
		defer cancel()
		e := j.Execute(ctx, value, h.Execute)
		return map[string]bool{"completed": e == nil}, e
	default:
		return nil, upgrade.ErrInvalid
	}
}

func deploymentCapacity(p upgrade.Plan) error {
	if upgrade.ValidateCapacity(p) != nil {
		return upgrade.ErrCapacity
	}
	c := *p.Inventory.Capacity
	digest := c.Digest
	c.Digest = ""
	raw, e := json.Marshal(c)
	sum := sha256.Sum256(raw)
	if e != nil || hex.EncodeToString(sum[:]) != digest {
		return upgrade.ErrCapacity
	}
	return nil
}
