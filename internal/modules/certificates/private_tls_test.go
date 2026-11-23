package certificates

import (
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/httpchallenge"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateTLSRenewalRequiresOwnPrivateKey(t *testing.T) {
	if _, e := ObtainPrivateTLS(t.Context(), PrivateTLSRequest{Origin: "https://owned.test", Names: []string{"api.owned.test"}, Purpose: "serverAuth", PrivateKey: []byte("invalid")}, nil); e == nil {
		t.Fatal("private TLS renewal accepted missing owning-role key")
	}
}

func TestPrivateLocalChallengeDoesNotOwnSharedBusinessTokens(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared, e := httpchallenge.New(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = shared.Reconcile(t.Context(), []app.HTTPChallenge{{Owner: "shared", Token: "business", KeyAuthorization: "business.authority"}}); e != nil {
		t.Fatal(e)
	}
	local, e := NewPrivateLocalHTTPChallenges(t.Context(), root)
	if e != nil {
		t.Fatal(e)
	}
	if e = local.PrepareCurrent(t.Context(), "role", "private", "private.authority"); e != nil {
		t.Fatal(e)
	}
	if e = shared.Reconcile(t.Context(), nil); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, ".well-known/acme-challenge/private")); e != nil {
		t.Fatal("shared cleanup removed private token", e)
	}
	if e = shared.Reconcile(t.Context(), []app.HTTPChallenge{{Owner: "shared", Token: "business", KeyAuthorization: "business.authority"}}); e != nil {
		t.Fatal(e)
	}
	// A cold role restart cleans only its own previously journalled token.
	if _, e = NewPrivateLocalHTTPChallenges(t.Context(), root); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, ".well-known/acme-challenge/private")); !os.IsNotExist(e) {
		t.Fatal("private stale token retained", e)
	}
	if _, e = os.Stat(filepath.Join(root, ".well-known/acme-challenge/business")); e != nil {
		t.Fatal("private cleanup removed business token", e)
	}
}
