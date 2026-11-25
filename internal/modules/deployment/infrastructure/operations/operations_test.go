package operations

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCloudMutationBindsRequestAndPreservesOtherBackend(t *testing.T) {
	var method, path, query string
	var patched map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`{"fingerprint":"owned","backends":[{"group":"https://www.googleapis.com/compute/v1/projects/owned/zones/us-west1-c/instanceGroups/a","balancingMode":"CONNECTION"},{"group":"https://www.googleapis.com/compute/v1/projects/owned/zones/us-west1-c/instanceGroups/b","balancingMode":"CONNECTION"}]}`))
			return
		}
		method, path, query = r.Method, r.URL.Path, r.URL.Query().Get("requestId")
		json.NewDecoder(r.Body).Decode(&patched)
		w.Write([]byte(`{"name":"operation-1","selfLink":"https://www.googleapis.com/compute/v1/projects/owned/regions/us-west1/operations/operation-1"}`))
	}))
	defer server.Close()
	n := domain.NodeDeployment{Node: domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, InstanceGroup: "projects/owned/zones/us-west1-c/instanceGroups/a", PublicBackend: "projects/owned/regions/us-west1/backendServices/public"}
	other := domain.NodeDeployment{InstanceGroup: "projects/owned/zones/us-west1-c/instanceGroups/b"}
	step := upgrade.Step{ID: "33333333-3333-4333-8333-333333333333-001", Kind: "public-remove", Node: n.Node, Targets: []domain.NodeDeployment{n, other}}
	c := Cloud{Endpoint: server.URL, Client: server.Client(), Token: func(context.Context) (string, error) { return "owned", nil }}
	if _, e := c.Mutate(t.Context(), step, n); e != nil {
		t.Fatal(e)
	}
	if method != "PATCH" || !strings.HasSuffix(path, "/backendServices/public") || query != RequestID(step.ID) || patched["fingerprint"] != "owned" || len(patched["backends"].([]any)) != 1 {
		t.Fatal("unsafe patch", patched, method, path, query)
	}
	method = ""
	step.Targets[1].InstanceGroup = "projects/owned/zones/us-west1-c/instanceGroups/c"
	if _, err := c.Mutate(t.Context(), step, n); err == nil || method != "" {
		t.Fatal("backend membership drift allowed a write")
	}
}
func TestRecoveryCannotUseArbitraryCloudOperation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"DONE","clientOperationId":"unrelated","targetLink":"unrelated"}`))
	}))
	defer s.Close()
	c := Cloud{Endpoint: s.URL, Client: s.Client(), Token: func(context.Context) (string, error) { return "owned", nil }}
	if e := c.VerifyOperation(t.Context(), upgrade.OperationRef{StepID: "33333333-3333-4333-8333-333333333333-001", CloudOperation: "projects/owned/regions/us-west1/operations/operation-1"}); e == nil {
		t.Fatal("unrelated operation accepted")
	}
}

func TestManagementWaitsForNativeAppliedDigest(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "gb-up-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e = os.Mkdir(filepath.Join(dir, "nginx-control"), 0700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(dir, "nginx-control", "control.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	os.Chmod(socket, 0600)
	digest := strings.Repeat("a", 64)
	control := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"desired_digest": digest})
	})}
	go control.Serve(listener)
	defer control.Close()
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"details": map[string]string{"management_config_digest": digest}})
	}))
	defer health.Close()
	addr, port, _ := net.SplitHostPort(strings.TrimPrefix(health.URL, "http://"))
	number, _ := strconv.Atoi(port)
	n := domain.NodeDeployment{Node: domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, PrivateAddress: addr, StoragePrefix: "owned", Roles: map[string]domain.RoleDeployment{"nginx": {HealthPort: number, ControlVolume: "owned-nginx-control"}}}
	h := LocalHost{Configuration: HostConfiguration{Node: n, StorageRoot: dir}}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if e = h.management(ctx, upgrade.Step{Node: n.Node, Kind: "management-remove", Targets: []domain.NodeDeployment{n}}); e != nil {
		t.Fatal("did not acknowledge actual native detail", e)
	}
}

type incompatibleRunner struct{}

func (incompatibleRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(`{"runtime_protocol":0,"boot_format":1,"schema_min":22,"schema_max":27}`), nil
}
func TestCandidateContractMustBeReadFromExactImage(t *testing.T) {
	h := LocalHost{Runner: incompatibleRunner{}}
	if e := h.verifyImageContract(t.Context(), "registry.test/api@sha256:"+strings.Repeat("a", 64)); e == nil {
		t.Fatal("unsupported candidate accepted from compatibility checkbox")
	}
}

type contractJSONRunner []byte

func (r contractJSONRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r), nil
}
func TestOldProtocolOneImageCannotIgnorePrivateTLSConfiguration(t *testing.T) {
	old := contractJSONRunner(`{"runtime_protocol":1,"boot_format":1,"schema_min":27,"schema_max":27,"role_min":6,"role_max":6}`)
	if (LocalHost{Runner: old}).verifyImageContract(t.Context(), "registry.test/api@sha256:"+strings.Repeat("a", 64)) == nil {
		t.Fatal("old config parser approved for new private TLS and safety configuration")
	}
	raw, _ := json.Marshal(domain.CurrentRuntimeContract())
	if e := (LocalHost{Runner: contractJSONRunner(raw)}).verifyImageContract(t.Context(), "registry.test/api@sha256:"+strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
}
