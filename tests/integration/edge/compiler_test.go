package edge_test

import (
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"testing"
)

func TestProtectedAddressAndUnmappedTLSNameFailClosed(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "::1", "fe80::1", "8.8.8.8"} {
		s := app.Snapshot{Version: "v1", Targets: []app.Target{{ID: "t1", Revision: 1, Config: app.TargetConfig{Protocol: "http", AllowedNetworks: []string{"0.0.0.0/0", "::/0"}, Members: []app.TargetMember{{Address: ip, Port: 80, Weight: 1}}}}}}
		if _, e := (nginx.Compiler{}).Compile(s, edge.RuntimeState{Generation: "g1"}); e == nil {
			t.Fatalf("accepted protected address %s", ip)
		}
	}
}
