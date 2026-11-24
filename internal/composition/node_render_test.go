package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/secrets"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestNodeRenderUsesPeerVPCAndIndependentRecipients(t *testing.T) {
	root := t.TempDir()
	// A shared checkout can be group-writable. Operator input must
	// remain protected: copy example fixtures into an owned private directory.
	templates := filepath.Join(root, "templates")
	for _, name := range []string{"edge/edge.example.json", "edge/api.example.json", "edge/worker.example.json", "pki/ca.example.json", "query/query.example.json", "nodes/b.example.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "deploy", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "edge/edge.example.json" {
			var template map[string]any
			if err := json.Unmarshal(data, &template); err != nil {
				t.Fatal(err)
			}
			template["protected_networks"] = []string{"10.42.0.30/32", "10.43.0.10/32"}
			data, err = json.Marshal(template)
			if err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(templates, name)
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(root, "b")
	raw, e := os.ReadFile(filepath.Join(templates, "nodes", "b.example.json"))
	if e != nil {
		t.Fatal(e)
	}
	var node domain.NodeDeployment
	if e = json.Unmarshal(raw, &node); e != nil {
		t.Fatal(e)
	}
	node.Node.ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	node.EnvironmentFile = out + ".env"
	node.Instance = "projects/owned/zones/us-west1-c/instances/gatebeam-b"
	node.InstanceGroup = "projects/owned/zones/us-west1-c/instanceGroups/gatebeam-b"
	node.PublicBackend = "projects/owned/regions/us-west1/backendServices/entry"
	node.PrivateBackend = "projects/owned/regions/us-west1/backendServices/ca"
	modes := map[string]string{"nginx": "edge", "management": "api", "background-jobs": "worker", "log-query": "query"}
	for name, r := range node.Roles {
		r.Image = "registry.example/gatebeam/" + name + "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		r.ConfigFile = filepath.Join(out, modes[name], modes[name]+".json")
		node.Roles[name] = r
	}
	policy := secrets.RolePolicy{}
	own := map[string]string{}
	for _, role := range []string{"api", "provider", "notification", "ca", "leaf"} {
		for i := 0; i < 2; i++ {
			file := filepath.Join(root, role+string(rune('a'+i)))
			if e = secrets.EnsureIdentity(file); e != nil {
				t.Fatal(e)
			}
			s, e := secrets.New(file)
			if e != nil {
				t.Fatal(e)
			}
			policy[role] = append(policy[role], s.Recipient())
			if i == 1 {
				own[role] = s.Recipient()
			}
		}
	}
	peer := node
	peer.Node.ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	peer.PrivateAddress = node.PeerAddress
	peer.PeerAddress = node.PrivateAddress
	peer.StoragePrefix = "gatebeam-a"
	peer.Instance = "projects/owned/zones/us-west1-c/instances/gatebeam-a"
	peer.InstanceGroup = "projects/owned/zones/us-west1-c/instanceGroups/gatebeam-a"
	peer.Roles = map[string]domain.RoleDeployment{}
	for name, r := range node.Roles {
		r.ControlVolume = "gatebeam-a-" + name + "-control"
		peer.Roles[name] = r
	}
	request := NodeRenderRequest{PeerNode: peer, Node: node, TemplatesDirectory: templates, OutputDirectory: out, Recipients: policy, NodeRecipients: own}
	if e = RenderNodeConfigs(context.Background(), request); e != nil {
		t.Fatal(e)
	}
	var edge map[string]any
	data, e := os.ReadFile(filepath.Join(out, "edge", "edge.json"))
	if e != nil || json.Unmarshal(data, &edge) != nil {
		t.Fatal(e)
	}
	if edge["node_id"] != node.Node.ID || edge["management_api_address"] != "10.42.0.31:9443" || edge["management_api_peer_address"] != "10.42.0.30:9443" || edge["certificate_recipient"] != own["leaf"] {
		t.Fatal("B reused A endpoints or identity", edge["node_id"])
	}
	var edgeNetworks struct {
		Protected []string `json:"protected_networks"`
	}
	if err := json.Unmarshal(data, &edgeNetworks); err != nil {
		t.Fatal(err)
	}
	wantProtected := []string{"10.42.0.30/32", "10.43.0.10/32", "10.42.0.31/32"}
	if !slices.Equal(edgeNetworks.Protected, wantProtected) {
		t.Fatalf("protected networks = %v, want %v", edgeNetworks.Protected, wantProtected)
	}
	var api struct {
		HealthEndpoints map[string]map[string]string `json:"health_endpoints"`
	}
	data, e = os.ReadFile(filepath.Join(out, "api", "api.json"))
	if e != nil || json.Unmarshal(data, &api) != nil {
		t.Fatal(e)
	}
	if api.HealthEndpoints[node.Node.ID]["nginx"] != "http://10.42.0.31:19091" || api.HealthEndpoints[peer.Node.ID]["management"] != "http://10.42.0.30:19092" {
		t.Fatal("rendered health inventory copied example IDs", api.HealthEndpoints)
	}
	env, e := os.ReadFile(out + ".env")
	if e != nil || !bytes.Contains(env, []byte("NODE_STORAGE_PREFIX=gatebeam-b")) || !bytes.Contains(env, []byte("@sha256:")) {
		t.Fatal("node environment not bound to inventory", e)
	}
	if e = RenderNodeConfigs(context.Background(), request); e == nil {
		t.Fatal("existing protected configuration overwritten")
	}
}
