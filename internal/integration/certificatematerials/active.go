package certificatematerials

import (
	"errors"
	cert "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/platform/transaction"
)

type BindingOwner interface {
	CurrentMaterialBindingsWithin(transaction.Scope) (release.VerifiedBindings, error)
}
type Active struct{ Owner BindingOwner }

func (a Active) ForSpecWithin(sc transaction.Scope, id string) ([]cert.ActiveBinding, error) {
	out := []cert.ActiveBinding{}
	r, e := a.Owner.CurrentMaterialBindingsWithin(sc)
	// No verified deployment is a real absence, not an inferred activation.
	if e != nil {
		if errors.Is(e, release.ErrNotFound) {
			return out, nil
		}
		return nil, e
	}
	for _, m := range r.Materials {
		if m.Kind == "certificate" && m.ID == id {
			out = append(out, cert.ActiveBinding{SpecRevision: m.Revision, VersionID: m.VersionID, Digest: m.Digest, ArtifactID: r.ArtifactID, Version: r.Version, Generation: r.Generation, VerifiedAt: r.VerifiedAt})
		}
	}
	return out, nil
}
