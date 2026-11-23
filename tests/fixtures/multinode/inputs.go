//go:build integration

package multinode

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

//go:embed config.json
var fixtureConfig []byte

//go:embed budget.json
var fixtureBudget []byte

func validateInputs(t testing.TB) {
	t.Helper()
	for name, want := range map[string][]byte{"GATEBEAM_MULTINODE_NODES": fixtureConfig, "GATEBEAM_MULTINODE_BUDGET": fixtureBudget} {
		path := os.Getenv(name)
		if path == "" {
			continue
		}
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
			t.Fatal("bounded explicit fixture input required")
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var actual, expected any
		if json.Unmarshal(raw, &actual) != nil || json.Unmarshal(want, &expected) != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatal("fixture nodes/budget differs from maintained owned contract")
		}
	}
}
func verifyRoleBudgets(t testing.TB, l *Lab) {
	t.Helper()
	var b struct {
		Roles map[string]struct {
			Memory int64   `json:"memory_bytes"`
			CPU    float64 `json:"cpu"`
			Pids   int64   `json:"pids"`
		}
	}
	if json.Unmarshal(fixtureBudget, &b) != nil {
		t.Fatal("invalid fixture budget")
	}
	var config struct {
		NodeIDs []string `json:"node_ids"`
	}
	if json.Unmarshal(fixtureConfig, &config) != nil {
		t.Fatal("invalid fixture nodes")
	}
	for index, n := range l.Nodes {
		if n.Info.Node.ID != config.NodeIDs[index] {
			t.Fatal("actual node identity differs from explicit fixture")
		}
		for role, limit := range b.Roles {
			id := n.Compose(t, "ps", "-q", role)
			raw := Docker(t, "inspect", "--format", "{{json .HostConfig}}", id)
			var actual struct{ Memory, NanoCpus, PidsLimit int64 }
			if json.NewDecoder(bytes.NewBufferString(raw)).Decode(&actual) != nil || actual.Memory != limit.Memory || actual.NanoCpus != int64(limit.CPU*1e9) || actual.PidsLimit != limit.Pids {
				t.Fatal("runtime resource budget drift", role, actual)
			}
		}
	}
}
