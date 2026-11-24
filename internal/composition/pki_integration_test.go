//go:build integration

package composition

import (
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"path/filepath"
	"testing"
)

func TestComposedPKIRejectsAPIAgeRecipient(t *testing.T) {
	p := testkit.Postgres(t)
	path := filepath.Join(t.TempDir(), "api.key")
	if e := secrets.EnsureIdentity(path); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = newAPIHandlerWithPKI(p, se, nil, bootstrap.Config{CARecipient: se.Recipient(), CAServerNames: []string{"host.example"}, CAClientNames: []string{"client.example"}}, authHTTP.Config{Origin: "http://localhost"}); e == nil {
		t.Fatal("API identity reused as CA EAB recipient")
	}
}
