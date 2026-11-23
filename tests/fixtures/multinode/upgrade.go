//go:build integration

package multinode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/operations"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"go.yaml.in/yaml/v3"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// UpgradeOperations uses actual role processes, owner controls, persisted image
// approval and volumes. Only cloud LB membership/fencing is an explicit fixture.
type UpgradeOperations struct {
	T                            testing.TB
	Lab                          *Lab
	Store                        repo.UpgradeStore
	Images                       map[string]string
	Calls                        []upgrade.Step
	Public, Private              map[string]bool
	ExecutorExited               *os.ProcessState
	AfterApply                   func(upgrade.Step)
	BeforeDrain                  func(upgrade.Step, string)
	AfterDrain                   func(upgrade.Step, string, time.Time)
	CrashAfterApply, CrashSignal string
	InterruptAfter               string
}

func NewUpgradeOperations(t testing.TB, l *Lab) *UpgradeOperations {
	l.Business(t)
	l.CanarySite(t)
	o := &UpgradeOperations{T: t, Lab: l, Store: repo.UpgradeStore{Pool: l.Pool}, Images: map[string]string{}, Public: map[string]bool{}, Private: map[string]bool{}}
	for _, n := range l.Nodes {
		o.Public[n.Info.Node.ID] = true
		o.Private[n.Info.Node.ID] = true
	}
	return o
}
func (o *UpgradeOperations) node(id string) *Node {
	for _, n := range o.Lab.Nodes {
		if n.Info.Node.ID == id {
			return n
		}
	}
	return nil
}
var errFixtureSnapshot = errors.New("bad fixture status")

func observationFailureClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection-refused"
	case errors.Is(err, errFixtureSnapshot):
		return "invalid-status"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	return "unclassified"
}

func probeClasses(state lifecycle.Snapshot) map[string]string {
	out := map[string]string{}
	for _, cap := range []string{lifecycle.Data, lifecycle.Management, lifecycle.GlobalJobs, lifecycle.LocalCleanup, lifecycle.ACME, lifecycle.Status, lifecycle.Query} {
		class := state.Details["probe_"+cap]
		switch class {
		case "ok", "deadline", "cancelled", "failed":
		default:
			class = "unreported"
		}
		out[cap] = class
	}
	return out
}

type upgradeObservation struct {
	state lifecycle.Snapshot
	class string
}

func (o *UpgradeOperations) Observe(ctx context.Context, id string) (upgrade.NodeState, error) {
	return o.observe(ctx, id, nil)
}
func (o *UpgradeOperations) observe(ctx context.Context, id string, captured map[string]upgradeObservation) (upgrade.NodeState, error) {
	n := o.node(id)
	if n == nil {
		return upgrade.NodeState{}, errors.New("unknown fixture node")
	}
	out := upgrade.NodeState{Ready: true, ControlReady: true, Images: map[string]string{}}
	for role := range Modes {
		s, e := o.snapshot(ctx, n, role)
		if captured != nil {
			captured[role] = upgradeObservation{state: s, class: observationFailureClass(e)}
		}
		if e != nil || !fixtureReady(role, s) {
			o.T.Logf("owned upgrade observation not ready: role=%s transport_error=%t live=%t mode=%s data=%t management=%t jobs=%t acme=%t status=%t query=%t", role, e != nil, s.Live, s.Mode, s.Ready["data"], s.Ready["management"], s.Ready["global-jobs"], s.Ready["acme"], s.Ready["status"], s.Ready["query"])
			out.Ready = false
			out.ControlReady = false
		}
		out.Images[role] = n.Info.Roles[role].Image
		if role == "nginx" {
			out.ArtifactID = s.Details["artifact_id"]
			out.Generation = s.Details["generation"]
		}
	}
	return out, nil
}
func fixtureReady(role string, s lifecycle.Snapshot) bool {
	if !s.Live || s.Mode != "serving" {
		return false
	}
	caps := map[string][]string{"nginx": {"data"}, "management": {"management"}, "background-jobs": {"global-jobs", "local-cleanup"}, "internal-ca": {"acme", "status"}, "log-query": {"query"}}
	for _, cap := range caps[role] {
		if !s.Ready[cap] {
			return false
		}
	}
	return true
}
func (o *UpgradeOperations) snapshot(ctx context.Context, n *Node, role string) (lifecycle.Snapshot, error) {
	var s lifecycle.Snapshot
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+n.Port(o.T, HealthPorts[role])+"/status", nil)
	client := &http.Client{Timeout: operations.HealthRequestTimeout}
	r, e := client.Do(req)
	if e != nil {
		return s, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&s) != nil {
		return s, errFixtureSnapshot
	}
	return s, nil
}
// A control acknowledgement records desired state; only the actual role's
// loaded target digest completes the operation. Parent cancellation still wins.
func (o *UpgradeOperations) waitManagementDigest(ctx context.Context, n *Node, digest string) (lifecycle.Snapshot, int, error) {
	observation, cancel := context.WithTimeout(ctx, operations.OperationObservationTimeout)
	defer cancel()
	var last lifecycle.Snapshot
	observations := 0
	for {
		state, err := o.snapshot(observation, n, "nginx")
		last = state
		observations++
		if err == nil && observation.Err() == nil && state.Details["management_config_digest"] == digest {
			return state, observations, nil
		}
		select {
		case <-observation.Done():
			return last, observations, observation.Err()
		case <-time.After(30 * time.Millisecond):
		}
	}
}

func (o *UpgradeOperations) Apply(ctx context.Context, s upgrade.Step) (upgrade.OperationRef, error) {
	o.Calls = append(o.Calls, s)
	op := upgrade.OperationRef{StepID: s.ID, HostCommandID: s.ID}
	n := o.node(s.Node.ID)
	if n == nil {
		return op, errors.New("unknown fixture node")
	}
	switch s.Kind {
	case "precheck", "compatibility":
		var schema int
		if e := o.Lab.Pool.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&schema); e != nil || schema != 27 {
			return op, errors.New("fixture schema not expanded")
		}
	case "recovery-check":
		for _, peer := range o.Lab.Nodes {
			if peer != n {
				state, e := o.Observe(ctx, peer.Info.Node.ID)
				if e != nil || !state.Ready {
					return op, errors.New("peer unavailable")
				}
			}
		}
	case "management-remove", "management-restore":
		// Both peers share one operation window; the second cannot reset it.
		observation, cancel := context.WithTimeout(ctx, operations.OperationObservationTimeout)
		defer cancel()
		for _, peer := range o.Lab.Nodes {
			if observation.Err() != nil {
				return op, errors.New("native management digest not applied")
			}
			raw := peer.Control(o.T, "nginx", "/management-upstreams", map[string]any{"address": net.JoinHostPort(n.Info.PrivateAddress, "9443"), "unavailable": s.Kind == "management-remove"})
			var ack struct {
				Digest string `json:"desired_digest"`
			}
			if json.Unmarshal(raw, &ack) != nil || len(ack.Digest) != 64 {
				return op, errors.New("missing derived digest")
			}
			started := time.Now()
			last, observations, observationError := o.waitManagementDigest(observation, peer, ack.Digest)
			if observationError != nil {
				elapsed := time.Since(started)
				observationClass := observationFailureClass(observationError)
				o.T.Cleanup(func() {
					if !o.T.Failed() {
						return
					}
					o.T.Logf("recorded management confirmation failure: elapsed=%s budget=%s observations=%d observed_digest_present=%t observation_class=%s probes=%v", elapsed, operations.OperationObservationTimeout, observations, len(last.Details["management_config_digest"]) == 64, observationClass, probeClasses(last))
					if o.Lab.Pool != nil {
						diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
						var states []byte
						err := o.Lab.Pool.QueryRow(diagnostic, `SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT status,count(*) FROM jobs WHERE target_node_id=$1 AND target_node_epoch=$2 AND kind='deployment.node.generation.v1' GROUP BY status) s`, peer.Info.Node.ID, peer.Info.Node.Epoch).Scan(&states)
						cancel()
						if err == nil {
							o.T.Log("management post-scenario job states", string(states))
						} else {
							o.T.Log("management post-scenario job states unavailable")
						}
					}
				})
				return op, errors.New("native management digest not applied")
			}
		}
	case "public-remove":
		o.Public[n.Info.Node.ID] = false
	case "private-remove":
		o.Private[n.Info.Node.ID] = false
	case "public-add":
		o.Public[n.Info.Node.ID] = true
	case "private-add":
		o.Private[n.Info.Node.ID] = true
	case "drain":
		deadline := time.Now().Add(time.Duration(s.Seconds) * time.Second).UTC()
		for _, role := range domain.NodeRoleNames() {
			if len(s.Images) == 0 || s.Images[role] != "" {
				if role == "background-jobs" {
					n.Control(o.T, role, "/maintenance", map[string]bool{"enabled": true})
					continue
				}
				if o.BeforeDrain != nil {
					o.BeforeDrain(s, role)
				}
				actual, e := o.drain(n, role, s.Seconds)
				if e != nil {
					return op, e
				}
				if o.AfterDrain != nil {
					o.AfterDrain(s, role, actual)
				}
				if actual.After(deadline) {
					deadline = actual
				}
			}
		}
		select {
		case <-ctx.Done():
			return op, ctx.Err()
		case <-time.After(time.Until(deadline)):
		}
	case "log-flush":
		Docker(o.T, "run", "--rm", "--network", "none", "--read-only", "--user", "101:101", "--cap-drop", "ALL", "-v", n.Info.StoragePrefix+"-edge-logs:/var/lib/gatebeam/logs", "-v", os.Getenv("GATEBEAM_COMPOSE_PROBE_BINARY")+":/capabilities:ro", "-e", "GATEBEAM_TEST_LOG_FSYNC=1", "--entrypoint", "/capabilities", "gatebeam-edge:local")
		var cutoff []map[string]any
		if json.Unmarshal(n.Control(o.T, "background-jobs", "/logs/cutoff", struct{}{}), &cutoff) != nil {
			return op, errors.New("invalid cutoff")
		}
		end := time.Now().Add(12 * time.Second)
		for {
			var proof struct {
				Ready bool `json:"ready"`
			}
			if json.Unmarshal(n.Control(o.T, "background-jobs", "/logs/cutoff/verify", cutoff), &proof) != nil {
				return op, errors.New("invalid cutoff receipt")
			}
			if proof.Ready {
				break
			}
			if time.Now().After(end) {
				return op, errors.New("cutoff incomplete")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if len(s.Images) == 0 || s.Images["background-jobs"] != "" {
			deadline, e := o.drain(n, "background-jobs", 1)
			if e != nil {
				return op, e
			}
			time.Sleep(time.Until(deadline))
		}
	case "approve-images":
		if e := o.Store.ApproveUpgradeImages(ctx, s); e != nil {
			return op, e
		}
	case "update":
		if e := o.update(s, n); e != nil {
			return op, e
		}
	case "verify-api", "verify-private", "verify-public":
		// Wait performs the actual probes so a successful dispatch is not readiness.
	case "observe":
		select {
		case <-ctx.Done():
			return op, ctx.Err()
		case <-time.After(time.Duration(s.Seconds) * time.Second):
		}
	case "host-stop":
		n.Compose(o.T, "stop", "--timeout", "2", "nginx", "management", "background-jobs", "internal-ca", "log-query")
	case "host-start":
		n.Compose(o.T, "start", "nginx", "management", "background-jobs", "internal-ca", "log-query")
	default:
		return op, errors.New("unknown fixture step")
	}
	if o.AfterApply != nil {
		o.AfterApply(s)
	}
	if o.CrashAfterApply == s.Kind {
		if os.WriteFile(o.CrashSignal+".ready", []byte(s.ID), 0600) != nil {
			os.Exit(78)
		}
		for {
			if _, e := os.Stat(o.CrashSignal + ".exit"); e == nil {
				os.Exit(77)
			}
			select {
			case <-ctx.Done():
				os.Exit(79)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if o.InterruptAfter == s.Kind {
		return op, context.DeadlineExceeded
	}
	return op, nil
}

func (o *UpgradeOperations) logRecordedProbes(captured map[string]upgradeObservation) {
	for _, role := range domain.NodeRoleNames() {
		row, exists := captured[role]
		if !exists {
			continue
		}
		s := row.state
		o.T.Logf("recorded upgrade probe: role=%s transport_class=%s live=%t mode=%s data=%t management=%t jobs=%t acme=%t status=%t query=%t probes=%v", role, row.class, s.Live, s.Mode, s.Ready["data"], s.Ready["management"], s.Ready["global-jobs"], s.Ready["acme"], s.Ready["status"], s.Ready["query"], probeClasses(s))
	}
}

// These reads run in cleanup only if the test ultimately failed. Expected
// rejected-version checks must not spend recovery deadlines on diagnostics.
// They never retry a gate, mutate authority or expose runtime payloads/materials.
func (o *UpgradeOperations) logFailedNodeStates(ctx context.Context, n *Node) {
	if o.Lab.Pool == nil {
		return
	}
	n.LogQueryCapabilityFailure(o.T)
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var state string
	var incarnationMatches bool
	err := o.Lab.Pool.QueryRow(diagnostic, `SELECT state,epoch=$2 FROM deployment_nodes WHERE id=$1`, n.Info.Node.ID, n.Info.Node.Epoch).Scan(&state, &incarnationMatches)
	if err == nil {
		switch state {
		case "active", "restricted", "disabled":
		default:
			state = "unclassified"
		}
		o.T.Logf("post-scenario registry state=%s incarnation_matches=%t", state, incarnationMatches)
	} else {
		o.T.Log("post-scenario registry state unavailable")
	}
	var jobs []byte
	if err := o.Lab.Pool.QueryRow(diagnostic, `SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT kind,status,count(*) FROM jobs WHERE target_node_id=$1 AND target_node_epoch=$2 AND kind IN ('deployment.node.apply.v1','deployment.node.generation.v1') GROUP BY kind,status) s`, n.Info.Node.ID, n.Info.Node.Epoch).Scan(&jobs); err == nil {
		o.T.Log("post-scenario runtime job states", string(jobs))
	} else {
		o.T.Log("post-scenario runtime job states unavailable")
	}
}

func (o *UpgradeOperations) drain(n *Node, role string, seconds int) (time.Time, error) {
	// Lab role configurations use drain_seconds=1. The standard control API
	// already supplies that duration when the absolute deadline is omitted.
	// Start it at the receiving process, after Docker CLI/exec preparation.
	if seconds != 1 {
		return time.Time{}, errors.New("owned drain duration differs from role configuration")
	}
	var state lifecycle.Snapshot
	if json.Unmarshal(n.Control(o.T, role, "/drain", struct{}{}), &state) != nil || state.Mode != "draining" || state.Deadline.IsZero() {
		return time.Time{}, errors.New("missing actual owned drain deadline")
	}
	return state.Deadline, nil
}
func (o *UpgradeOperations) Wait(ctx context.Context, op upgrade.OperationRef) error {
	var s upgrade.Step
	for _, v := range o.Calls {
		if v.ID == op.StepID {
			s = v
		}
	}
	n := o.node(s.Node.ID)
	if n == nil {
		return errors.New("unknown fixture operation")
	}
	if s.Kind == "update" {
		// Completion proves the container/config replacement, not application health.
		// The separate verify-api step decides whether that completed new version is usable.
		for role, image := range s.Images {
			cid := n.Compose(o.T, "ps", "-a", "-q", role)
			actual := Docker(o.T, "inspect", "--format", "{{.Image}}", cid)
			started := Docker(o.T, "inspect", "--format", "{{.State.StartedAt}}", cid)
			if actual != strings.Split(image, "@")[1] || strings.HasPrefix(started, "0001-") {
				return errors.New("in-flight replacement not completed")
			}
			raw, e := os.ReadFile(filepath.Join(n.Secrets[role], Modes[role]+".json"))
			if e != nil {
				return e
			}
			var config bootstrap.Config
			if json.Unmarshal(raw, &config) != nil || config.ImageDigest != actual {
				return errors.New("in-flight config not completed")
			}
			n.Configs[role] = config
			next := map[string]domain.RoleDeployment{}
			for k, v := range n.Info.Roles {
				next[k] = v
			}
			r := next[role]
			r.Image = image
			next[role] = r
			n.Info.Roles = next
		}
		return nil
	}

	if s.Kind == "verify-api" || s.Kind == "verify-private" || s.Kind == "verify-public" || s.Kind == "observe" {
		// Use the real upgrade owner's existing readiness/canary contract.
		deadline := time.Now().Add(operations.VerificationTimeout)
		ctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		observations, lastReady := 0, false
		readyObservations, canaryAttempts := 0, 0
		var observationTime time.Duration
		captured := map[string]upgradeObservation{}
		verified := false
		// Control helpers can stop the test immediately. Preserve the same
		// failed-test-only evidence on that path as on a normal failed return.
		defer func() {
			if !verified {
				o.T.Cleanup(func() {
					if o.T.Failed() {
						o.logRecordedProbes(captured)
						o.logFailedNodeStates(ctx, n)
					}
				})
			}
		}()
		for time.Now().Before(deadline) && ctx.Err() == nil {
			observedAt := time.Now()
			state, e := o.observe(ctx, n.Info.Node.ID, captured)
			observationTime += time.Since(observedAt)
			observations++
			lastReady = e == nil && state.Ready
			if e == nil && state.Ready {
				readyObservations++
				if s.Kind == "verify-private" {
					r, e := n.CAClient.Get("https://ca.dual.test:8444/acme/server/directory")
					if e == nil {
						r.Body.Close()
						if r.StatusCode == 200 && ctx.Err() == nil {
							verified = true
							return nil
						}
					}
				} else if s.Kind == "verify-api" {
					canaryAttempts++
					b := o.Lab.BusinessInstance
					spec := operations.CanarySpec{SessionCookie: b.Session.Cookie, CSRFToken: b.Session.CSRF, SiteID: o.Lab.CanarySiteID}
					if e := operations.VerifyManagementCanary(ctx, n.APIClient, "https://management-api.dual.test", "https://management.dual.test", spec, true, s.ID); e == nil {
						n.Control(o.T, "background-jobs", "/capabilities/verify", struct{}{})
						if ctx.Err() == nil {
							verified = true
							return nil
						}
					}
				} else {
					b := o.Lab.BusinessInstance
					spec := operations.CanarySpec{SessionCookie: b.Session.Cookie, CSRFToken: b.Session.CSRF, SiteID: o.Lab.CanarySiteID}
					if e := operations.VerifyManagementCanary(ctx, n.PublicClient, "https://management.dual.test", "https://management.dual.test", spec, false, s.ID); e == nil && b.Get(o.T, n, "/") == 200 && ctx.Err() == nil {
						verified = true
						return nil
					}
				}
			}
			time.Sleep(40 * time.Millisecond)
		}
		o.T.Logf("owned upgrade verification failed: kind=%s observations=%d observation_time=%s last_roles_ready=%t ready_observations=%d canary_attempts=%d", s.Kind, observations, observationTime, lastReady, readyObservations, canaryAttempts)
		if s.Kind == "verify-api" {
			return upgrade.ErrFailed
		}
		return errors.New("actual fixture verification failed")
	}
	return nil
}
func (o *UpgradeOperations) VerifyRecovery(ctx context.Context, p upgrade.RecoveryProof) error {
	if o.ExecutorExited == nil || !o.ExecutorExited.Exited() {
		return errors.New("old fixture executor not fenced")
	}
	for _, op := range p.Operations {
		if e := o.Wait(ctx, op); e != nil {
			return e
		}
	}
	return nil
}
func (o *UpgradeOperations) update(s upgrade.Step, n *Node) error {
	raw, e := os.ReadFile(n.ComposeFile)
	if e != nil {
		return e
	}
	var model map[string]any
	if yaml.Unmarshal(raw, &model) != nil {
		return errors.New("compose fixture")
	}
	for _, role := range domain.NodeRoleNames() {
		image, changed := s.Images[role]
		if !changed {
			continue
		}
		local := o.Images[image]
		if local == "" {
			return errors.New("owned prebuilt image mapping required")
		}
		c := n.Configs[role]
		c.ImageDigest = strings.Split(image, "@")[1]
		n.Configs[role] = c
		body, e := json.Marshal(c)
		if e != nil {
			return e
		}
		path := filepath.Join(n.Secrets[role], c.Mode+".json")
		if e = os.WriteFile(path, body, 0600); e != nil {
			return e
		}
		helper := n.Info.StoragePrefix + "-update-" + fmt.Sprint(time.Now().UnixNano())
		Docker(o.T, "create", "--name", helper, "--network", "none", "-v", n.Info.StoragePrefix+"-"+role+"-secret:/dest", "gatebeam-edge:local")
		Docker(o.T, "cp", path, helper+":/dest/"+c.Mode+".json")
		Docker(o.T, "rm", helper)
		Docker(o.T, "run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE", "-v", n.Info.StoragePrefix+"-"+role+"-secret:/dest", "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "chmod 600 /dest/"+c.Mode+".json; chown 101:101 /dest/"+c.Mode+".json")
		model["services"].(map[string]any)[role].(map[string]any)["image"] = local
		// Break aliasing with the original immutable inventory retained by the plan.
		next := map[string]domain.RoleDeployment{}
		for k, v := range n.Info.Roles {
			next[k] = v
		}
		r := next[role]
		r.Image = image
		next[role] = r
		n.Info.Roles = next
	}
	raw, e = yaml.Marshal(model)
	if e != nil {
		return e
	}
	if e = os.WriteFile(n.ComposeFile, raw, 0600); e != nil {
		return e
	}
	args := []string{"up", "-d", "--no-build", "--no-deps", "--pull", "never", "--force-recreate"}
	for _, role := range domain.NodeRoleNames() {
		if s.Images[role] != "" {
			args = append(args, role)
		}
	}
	n.Compose(o.T, args...)
	return nil
}
