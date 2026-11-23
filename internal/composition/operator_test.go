package composition

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorRequiresOwnedInputsForRoleVerification(t *testing.T) {
	for _, mode := range []string{"api", "worker", "ca", "edge", "query"} {
		if _, e := MaintainRoleSecrets(context.Background(), bootstrap.Config{Mode: mode}, true); e == nil {
			t.Fatal("missing own keys/database silently passed", mode)
		}
	}
	p := filepath.Join(t.TempDir(), "request.json")
	if e := os.WriteFile(p, []byte(`{"node":{"id":"11111111-1111-4111-8111-111111111111","epoch":1}}`), 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := OperatorOperation(context.Background(), "validate-node", "", p); e == nil {
		t.Fatal("writable/unbounded node inventory accepted")
	}
}
