package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var ErrOperation = errors.New("provider or gateway operation unavailable or unverified")

const computeEndpoint = "https://compute.googleapis.com/compute/v1"

var operationPath = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{0,62}/(regions|zones)/[a-z0-9-]+/operations/[a-zA-Z0-9-]+$`)
var backendPath = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{0,62}/regions/[a-z0-9-]+/backendServices/[a-z][a-z0-9-]{0,62}$`)
var groupPath = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{0,62}/zones/[a-z0-9-]+/instanceGroups/[a-z][a-z0-9-]{0,62}$`)
var stepID = regexp.MustCompile(`^[0-9a-f-]{36}-[0-9]{3,4}$`)

// RequestID uses Compute Engine's standard UUID requestId deduplication field.
func RequestID(id string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("gatebeam-upgrade/"+id)).String()
}

type Cloud struct {
	Endpoint string
	Client   *http.Client
	Token    func(context.Context) (string, error)
}

func GcloudToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token", "--quiet").Output()
	if e != nil || len(b) > 8192 {
		return "", ErrOperation
	}
	token := strings.TrimSpace(string(b))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", ErrOperation
	}
	return token, nil
}
func (c Cloud) request(ctx context.Context, method, path string, body any, out any) error {
	if c.Token == nil {
		return ErrOperation
	}
	token, e := c.Token(ctx)
	if e != nil {
		return ErrOperation
	}
	var raw []byte
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return ErrOperation
		}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = computeEndpoint
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint+"/"+path, bytes.NewReader(raw))
	if e != nil {
		return ErrOperation
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, e := client.Do(req)
	if e != nil {
		return ErrOperation
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrOperation
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if e != nil || len(b) > 1<<20 || json.Unmarshal(b, out) != nil {
		return ErrOperation
	}
	return nil
}
func resourcePath(s string) string {
	for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		s = strings.TrimPrefix(s, prefix)
	}
	return s
}
func (c Cloud) InstanceStopped(ctx context.Context, ref string) error {
	if !domain.ValidInstanceReference(ref) {
		return ErrOperation
	}
	var v struct{ Status string }
	if c.request(ctx, "GET", ref, nil, &v) != nil || v.Status != "TERMINATED" {
		return ErrOperation
	}
	return nil
}
func (c Cloud) Mutate(ctx context.Context, s upgrade.Step, n domain.NodeDeployment) (upgrade.OperationRef, error) {
	op := upgrade.OperationRef{StepID: s.ID}
	if !stepID.MatchString(s.ID) || s.Node != n.Node {
		return op, ErrOperation
	}
	method, path := "PATCH", n.PublicBackend
	var body any
	switch s.Kind {
	case "public-remove", "public-add", "private-remove", "private-add":
		if strings.HasPrefix(s.Kind, "private-") {
			path = n.PrivateBackend
		}
		if !backendPath.MatchString(path) || !groupPath.MatchString(n.InstanceGroup) {
			return op, ErrOperation
		}
		var current struct {
			Fingerprint string
			Backends    []map[string]any
		}
		if c.request(ctx, "GET", path, nil, &current) != nil || current.Fingerprint == "" {
			return op, ErrOperation
		}
		adding := strings.HasSuffix(s.Kind, "-add")
		expectedAbsent := ""
		if adding {
			expectedAbsent = n.InstanceGroup
		}
		if len(s.Targets) < 2 || !backendMembersMatch(current.Backends, s.Targets, expectedAbsent) {
			return op, ErrOperation
		}
		next := make([]map[string]any, 0, len(s.Targets))
		for _, member := range current.Backends {
			group, _ := member["group"].(string)
			if resourcePath(group) != n.InstanceGroup {
				next = append(next, member)
			}
		}
		if adding {
			next = append(next, map[string]any{"group": "https://www.googleapis.com/compute/v1/" + n.InstanceGroup, "balancingMode": "CONNECTION"})
		}
		body = map[string]any{"fingerprint": current.Fingerprint, "backends": next}
	case "host-stop", "host-start":
		if !domain.ValidInstanceReference(n.Instance) {
			return op, ErrOperation
		}
		method = "POST"
		path = n.Instance + "/" + strings.TrimPrefix(s.Kind, "host-")
		body = map[string]any{}
	default:
		return op, ErrOperation
	}
	var result struct{ Name, SelfLink string }
	if c.request(ctx, method, path+"?requestId="+RequestID(s.ID), body, &result) != nil {
		return op, ErrOperation
	}
	op.CloudOperation = resourcePath(result.SelfLink)
	if !operationPath.MatchString(op.CloudOperation) {
		return op, ErrOperation
	}
	return op, nil
}
func (c Cloud) VerifyOperation(ctx context.Context, op upgrade.OperationRef) error {
	if !stepID.MatchString(op.StepID) || !operationPath.MatchString(op.CloudOperation) {
		return ErrOperation
	}
	var result struct {
		Status, ClientOperationId string
		Error                     *json.RawMessage
	}
	if c.request(ctx, "GET", op.CloudOperation, nil, &result) != nil || result.Status != "DONE" || result.Error != nil || result.ClientOperationId != RequestID(op.StepID) {
		return ErrOperation
	}
	return nil
}
func (c Cloud) VerifyMembership(ctx context.Context, n domain.NodeDeployment, private, present bool) error {
	path := n.PublicBackend
	if private {
		path = n.PrivateBackend
	}
	if !backendPath.MatchString(path) {
		return ErrOperation
	}
	var v struct{ Backends []struct{ Group string } }
	if c.request(ctx, "GET", path, nil, &v) != nil {
		return ErrOperation
	}
	found := 0
	for _, b := range v.Backends {
		if resourcePath(b.Group) == n.InstanceGroup {
			found++
		}
	}
	if present && found != 1 || !present && found != 0 {
		return ErrOperation
	}
	return nil
}

func minimalMember(m map[string]any) bool {
	for key, value := range m {
		switch key {
		case "group":
		case "balancingMode":
			if value != "CONNECTION" {
				return false
			}
		case "failover":
			if value != false {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func backendMembersMatch(backends []map[string]any, nodes []domain.NodeDeployment, absent string) bool {
	expected := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		if node.InstanceGroup != absent {
			expected[node.InstanceGroup] = true
		}
	}
	if len(expected) != len(backends) {
		return false
	}
	for _, member := range backends {
		group, _ := member["group"].(string)
		group = resourcePath(group)
		if !expected[group] || !minimalMember(member) {
			return false
		}
		delete(expected, group)
	}
	return true
}

// CheckInventory refuses proxy backends, foreign groups and custom membership
// policies. Each node is in its own dedicated CONNECTION-mode group.
func (c Cloud) CheckInventory(ctx context.Context, nodes []domain.NodeDeployment) error {
	if domain.ValidateNodeInventory(nodes) != nil {
		return ErrOperation
	}
	for _, entry := range []struct{ path, scheme string }{{nodes[0].PublicBackend, "EXTERNAL"}, {nodes[0].PrivateBackend, "INTERNAL"}} {
		var v struct {
			Protocol, LoadBalancingScheme string
			Backends                      []map[string]any
		}
		if c.request(ctx, "GET", entry.path, nil, &v) != nil || v.Protocol != "TCP" || v.LoadBalancingScheme != entry.scheme || !backendMembersMatch(v.Backends, nodes, "") {
			return ErrOperation
		}
	}
	for _, n := range nodes {
		var members struct{ Items []struct{ Instance string } }
		if c.request(ctx, "POST", n.InstanceGroup+"/listInstances", map[string]string{"instanceState": "ALL"}, &members) != nil || len(members.Items) != 1 || resourcePath(members.Items[0].Instance) != n.Instance {
			return ErrOperation
		}
	}
	return nil
}
func (c Cloud) BackendHealthy(ctx context.Context, n domain.NodeDeployment, private bool) error {
	path := n.PublicBackend
	if private {
		path = n.PrivateBackend
	}
	var v struct {
		HealthStatus []struct{ Instance, HealthState string }
	}
	if c.request(ctx, "POST", path+"/getHealth", map[string]string{"group": "https://www.googleapis.com/compute/v1/" + n.InstanceGroup}, &v) != nil || len(v.HealthStatus) == 0 {
		return ErrOperation
	}
	for _, h := range v.HealthStatus {
		if resourcePath(h.Instance) != n.Instance || h.HealthState != "HEALTHY" {
			return ErrOperation
		}
	}
	return nil
}

func (c Cloud) CheckCapacity(ctx context.Context, nodes []domain.NodeDeployment, evidence *domain.CapacityEvidence) error {
	if evidence == nil {
		return upgrade.ErrCapacity
	}
	for _, n := range nodes {
		var actual struct{ MachineType string }
		if c.request(ctx, "GET", n.Instance, nil, &actual) != nil {
			return upgrade.ErrCapacity
		}
		matched := false
		for _, trial := range evidence.Trials {
			if trial.Node == n.Node {
				if resourcePath(actual.MachineType) != trial.MachineType {
					return upgrade.ErrCapacity
				}
				matched = true
			}
		}
		if !matched {
			return upgrade.ErrCapacity
		}
	}
	return nil
}
