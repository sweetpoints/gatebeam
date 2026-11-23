package certificatematerials_test

import (
	"gatebeam/internal/integration/certificatematerials"
	cert "gatebeam/internal/modules/certificates/application"
	deploy "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/platform/transaction"
	"testing"
)

type materialOwner struct{ materials cert.Materials }

func (materialOwner) ValidateMaterialsWithin(transaction.Scope, []cert.MaterialRef) error { return nil }
func (o materialOwner) ReadMaterialsWithin(transaction.Scope, []cert.MaterialRef) (cert.Materials, error) {
	return o.materials, nil
}
func TestIndependentTrustProfilesShareEffectiveResolver(t *testing.T) {
	materials := cert.Materials{Generation: "materials", Items: []cert.Material{
		{Ref: cert.MaterialRef{ID: "client-trust", Revision: 1}, Status: &cert.StatusAttestation{ProfileDigest: "client-issuer-profile", ResolverServers: []string{"10.0.0.53:53"}}},
		{Ref: cert.MaterialRef{ID: "upstream-trust", Revision: 2}, Status: &cert.StatusAttestation{ProfileDigest: "upstream-issuer-profile", ResolverServers: []string{"10.0.0.53:53"}}},
	}}
	bind := func() (edge.RuntimeState, error) {
		return (certificatematerials.Adapter{Owner: materialOwner{materials}}).BindWithin(nil, deploy.Snapshot{}, edge.RuntimeState{})
	}
	first, e := bind()
	if e != nil {
		t.Fatal("compatible resolver profiles rejected", e)
	}
	if first.OCSPResolver == nil || len(first.Materials) != 2 {
		t.Fatal("trust omitted")
	}
	materials.Items[0], materials.Items[1] = materials.Items[1], materials.Items[0]
	reordered, e := bind()
	if e != nil || reordered.OCSPResolver.Generation != first.OCSPResolver.Generation {
		t.Fatal("profile aggregation depends on ordering", e)
	}
	materials.Items[0].Status.ProfileDigest = "changed-profile"
	changed, e := bind()
	if e != nil || changed.OCSPResolver.Generation == first.OCSPResolver.Generation {
		t.Fatal("profile authority change omitted", e)
	}
	materials.Items[0].Status.ResolverServers = []string{"10.0.1.53:53"}
	if _, e = bind(); e == nil {
		t.Fatal("genuinely incompatible resolver accepted")
	}
}
