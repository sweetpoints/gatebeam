package composition

import (
	"context"
	"errors"
	"gatebeam/internal/platform/bootstrap"
	"testing"
)

func TestAPIRejectsCASigningCapability(t *testing.T) {
	for _, cfg := range []bootstrap.Config{{CASignerFile: "must-not-open"}, {CAIdentityFile: "must-not-open"}, {OfflineRootDirectory: "must-not-open"}} {
		if e := Run(context.Background(), "api", cfg); !errors.Is(e, ErrProcessCapability) {
			t.Fatalf("API must reject CA capability before assembly: %v", e)
		}
	}
}
func TestCARequiresExplicitPrivateListenerAndTLS(t *testing.T) {
	for _, addr := range []string{"", ":443", "0.0.0.0:443", "[::]:443", "8.8.8.8:443", "example.test:443"} {
		if e := validateCAConfig(bootstrap.Config{CAListen: addr}); e == nil {
			t.Fatalf("invalid CA listener accepted %q", addr)
		}
	}
}
