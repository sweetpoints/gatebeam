package domain

import (
	"strings"
	"testing"
)

func TestNodeDeploymentRequiresFixedIndependentRoles(t *testing.T) {
	m := NodeDeployment{Node: NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, PrivateAddress: "10.42.0.30", PeerAddress: "10.42.0.31", Instance: "projects/owned/zones/us-west1-c/instances/gateway-a", InstanceGroup: "projects/owned/zones/us-west1-c/instanceGroups/gateway-a", PublicBackend: "projects/owned/regions/us-west1/backendServices/entry", PrivateBackend: "projects/owned/regions/us-west1/backendServices/ca", ComposeFile: "/opt/gatebeam/compose.yaml", EnvironmentFile: "/etc/gatebeam/a.env", StoragePrefix: "gatebeam-a", Roles: map[string]RoleDeployment{}}
	for i, name := range []string{"nginx", "management", "background-jobs", "log-query"} {
		m.Roles[name] = RoleDeployment{Image: "registry.example/gatebeam/" + name + "@sha256:" + strings.Repeat("a", 64), Protocol: 1, ConfigFile: "/etc/gatebeam/a/" + name + ".json", HealthPort: 19091 + i, ControlVolume: "gatebeam-a-" + name + "-control"}
	}
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	original := m.Roles["nginx"]
	bad := original
	bad.Image = "gatebeam-edge:latest"
	m.Roles["nginx"] = bad
	if m.Validate() == nil {
		t.Fatal("mutable image accepted")
	}
	m.Roles["nginx"] = original
	m.PeerAddress = m.PrivateAddress
	if m.Validate() == nil {
		t.Fatal("same node listed twice")
	}
	m.PeerAddress = "10.42.0.31"
	m.PrivateAddress = "203.0.113.25"
	if m.Validate() == nil {
		t.Fatal("backend public address accepted for private role bindings")
	}
}
