package operations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"os/exec"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).Output()
	if e != nil || len(b) > 1<<20 {
		return nil, ErrOperation
	}
	return b, nil
}

type SSHHost struct{ Runner CommandRunner }

func (h SSHHost) call(ctx context.Context, n domain.NodeDeployment, flag, value string, out any) error {
	if n.Validate() != nil || !strings.HasPrefix(flag, "--") {
		return ErrOperation
	}
	parts := strings.Split(n.Instance, "/")
	runner := h.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	command := "sudo -n /usr/local/bin/gatebeam-deploy-host " + flag + " " + value
	raw, e := runner.Run(ctx, "gcloud", "compute", "ssh", parts[5], "--project="+parts[1], "--zone="+parts[3], "--internal-ip", "--strict-host-key-checking=yes", "--quiet", "--command="+command)
	if e != nil || json.Unmarshal(raw, out) != nil {
		return ErrOperation
	}
	return nil
}
func (h SSHHost) Observe(ctx context.Context, n domain.NodeDeployment) (upgrade.NodeState, error) {
	var out upgrade.NodeState
	e := h.call(ctx, n, "--status", n.Node.ID, &out)
	return out, e
}
func hostTargets(s upgrade.Step) []domain.NodeDeployment {
	if s.Kind == "management-remove" || s.Kind == "management-restore" || s.Kind == "precheck" || s.Kind == "recovery-check" {
		return s.Targets
	}
	for _, n := range s.Targets {
		if n.Node == s.Node {
			return []domain.NodeDeployment{n}
		}
	}
	return nil
}
func (h SSHHost) Start(ctx context.Context, s upgrade.Step) (upgrade.OperationRef, error) {
	op := upgrade.OperationRef{StepID: s.ID, HostCommandID: s.ID}
	raw, e := json.Marshal(s)
	if e != nil || !stepID.MatchString(s.ID) || len(hostTargets(s)) == 0 {
		return op, ErrOperation
	}
	for _, n := range hostTargets(s) {
		var result struct{ Accepted bool }
		if h.call(ctx, n, "--dispatch", base64.RawURLEncoding.EncodeToString(raw), &result) != nil || !result.Accepted {
			return op, ErrOperation
		}
	}
	return op, nil
}

type HostReceipt struct{ StepID, State, IntentDigest string }

func (h SSHHost) Completed(ctx context.Context, s upgrade.Step) error {
	for _, n := range hostTargets(s) {
		var receipt HostReceipt
		if h.call(ctx, n, "--receipt", s.ID, &receipt) != nil || receipt.StepID != s.ID || receipt.IntentDigest != IntentDigest(s) {
			return ErrOperation
		}
		if receipt.State == "failed" && s.Kind == "verify-api" {
			return upgrade.ErrFailed
		}
		if receipt.State == "unknown" {
			return upgrade.ErrPaused
		}
		if receipt.State != "succeeded" {
			return ErrOperation
		}
	}
	return nil
}
