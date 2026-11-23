package certificates_test

import (
	"context"
	"gatebeam/internal/modules/certificates"
	"gatebeam/internal/platform/secrets"
	"os"
	"path/filepath"
	"testing"
)

func TestAssembliesRequireDistinctActualAgeIdentities(t *testing.T) {
	leafFile := filepath.Join(t.TempDir(), "leaf.agekey")
	providerFile := filepath.Join(t.TempDir(), "provider.agekey")
	if e := secrets.EnsureIdentity(leafFile); e != nil {
		t.Fatal(e)
	}
	leaf, e := secrets.New(leafFile)
	if e != nil {
		t.Fatal(e)
	}
	copyKey, e := os.ReadFile(leafFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(providerFile, copyKey, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = certificates.NewWorker(nil, nil, providerFile, leaf.Recipient(), ""); e == nil {
		t.Fatal("same actual key at different paths accepted")
	}
	if _, _, e = certificates.NewManagement(nil, nil, nil, leaf.Recipient(), leaf.Recipient()); e == nil {
		t.Fatal("API accepted shared public recipient")
	}
	if _, e = certificates.NewEdge(nil, nil, leafFile, leaf.Recipient()); e == nil {
		t.Fatal("edge accepted provider decryption key")
	}
	if e = os.Remove(providerFile); e != nil {
		t.Fatal(e)
	}
	if e = secrets.EnsureIdentity(providerFile); e != nil {
		t.Fatal(e)
	}
	provider, e := secrets.New(providerFile)
	if e != nil {
		t.Fatal(e)
	}
	// Edge assembly needs only the leaf identity and the public provider recipient.
	if e = os.Remove(providerFile); e != nil {
		t.Fatal(e)
	}
	edge, e := certificates.NewEdge(nil, nil, leafFile, provider.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = edge.Ensure(context.Background(), "any-spec"); e == nil {
		t.Fatal("edge acquired an issuer capability")
	}
	if _, e = certificates.NewWorker(nil, nil, providerFile, leaf.Recipient(), ""); e == nil {
		t.Fatal("worker did not require its provider identity")
	}
}
