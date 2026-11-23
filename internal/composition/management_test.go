package composition

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"net/netip"
	"testing"
)

func TestOperatorBooleanCannotDeclareManagementTLSReady(t *testing.T) {
	e := verifyManagement(context.Background(), bootstrap.Config{HTTPSGatewayReady: true, APIOrigin: "https://management.test"})
	if e == nil {
		t.Fatal("operator flag accepted without measured serving TLS")
	}
}
func TestAPIOnlyBindsDeclaredPrivateManagementAddress(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", "8.8.8.8:8080", "172.30.0.4:8080"} {
		if e := validateAPIListen(bootstrap.Config{APIListen: address, APIPrivateNetwork: "172.30.0.0/30"}); e == nil {
			t.Fatalf("unrestricted API bind accepted: %s", address)
		}
	}
	if e := validateAPIListen(bootstrap.Config{APIListen: "172.30.0.3:8080", APIPrivateNetwork: "172.30.0.0/29"}); e != nil {
		t.Fatal(e)
	}
	if e := validateAPIListen(bootstrap.Config{APIListen: "127.0.0.1:8080"}); e != nil {
		t.Fatal(e)
	}
}

func TestManagementProtectionAllowsBusinessInSameGCPSubnet(t *testing.T) {
	cfg := bootstrap.Config{ManagementAPIAddress: "10.42.0.30:8080", ManagementAPIPeerAddress: "10.42.0.31:8080", APIPrivateNetwork: "10.42.0.0/20"}
	protected, e := runtimeProtected(cfg)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"10.42.0.30", "10.42.0.31"} {
		address := netip.MustParseAddr(raw)
		found := false
		for _, network := range protected {
			found = found || network.Contains(address)
		}
		if !found {
			t.Fatal("control host unprotected", raw)
		}
	}
	for _, raw := range []string{"10.42.0.24", "10.42.0.25", "10.42.0.26"} {
		address := netip.MustParseAddr(raw)
		for _, network := range protected {
			if network.Contains(address) {
				t.Fatal("management bind subnet incorrectly blocks business backend", raw, network)
			}
		}
	}
}

func TestProtectedPrivateTLSRoleAddressesAllowDeclaredPorts(t *testing.T) {
	for _, c := range []bootstrap.Config{{Mode: "api", APIListen: "10.42.0.30:9443", APITLSCertificateFile: "/owned/api.pem", APIPrivateNetwork: "10.42.0.0/20"}, {Mode: "worker", ManagementAPIAddress: "10.42.0.30:9443"}} {
		protected, e := runtimeProtected(c)
		if e != nil || len(protected) == 0 || !protected[0].Contains(netip.MustParseAddr("10.42.0.30")) {
			t.Fatal("private TLS transport rejected by unrelated legacy HTTP port restriction", c.Mode, e)
		}
	}
}
