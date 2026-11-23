package composition

import (
	"context"
	"errors"
	"gatebeam/internal/platform/bootstrap"
	"net/netip"
	"testing"
)

func TestRunUnavailableAndCancellation(t *testing.T) {

	if err := Run(context.Background(), "bogus", bootstrap.Config{}); !errors.Is(err, ErrUnsupportedMode) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, "api", bootstrap.Config{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMigrateRequiresDatabaseSecret(t *testing.T) {
	if err := Run(context.Background(), "migrate", bootstrap.Config{}); err == nil || errors.Is(err, ErrNotImplemented) {
		t.Fatalf("migration must access configured database: %v", err)
	}
}

func TestAPIAndBootstrapFailClosedWithoutConfiguration(t *testing.T) {
	for _, mode := range []string{"api", "bootstrap", "edge", "worker", "ca", "ca-bootstrap", "query"} {
		if e := Run(context.Background(), mode, bootstrap.Config{}); e == nil || errors.Is(e, ErrNotImplemented) {
			t.Fatalf("%s did not validate runtime configuration: %v", mode, e)
		}
	}
}

func TestPreflightProtectsExistingAPIBootstrapAddress(t *testing.T) {
	protected, e := runtimeProtected(bootstrap.Config{APIListen: "172.30.0.3:8080", APIPrivateNetwork: "172.30.0.0/29"})
	if e != nil {
		t.Fatal("existing API bootstrap must not require an edge-only field", e)
	}
	found := false
	for _, p := range protected {
		if p.Contains(netip.MustParseAddr("172.30.0.3")) {
			found = true
		}
	}
	if !found {
		t.Fatal("management API host not protected")
	}
}

func TestExplicitProtectedNetworkStillDeniesWholeControlSubnet(t *testing.T) {
	protected, e := runtimeProtected(bootstrap.Config{APIListen: "172.30.0.3:8080", APIPrivateNetwork: "172.30.0.0/29", ProtectedNetworks: []string{"172.30.0.0/29"}})
	if e != nil {
		t.Fatal(e)
	}
	for _, network := range protected {
		if network.Contains(netip.MustParseAddr("172.30.0.2")) {
			return
		}
	}
	t.Fatal("explicit control-network protection ignored")
}
