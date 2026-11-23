package certificatematerials

import (
	cert "gatebeam/internal/modules/certificates/application"
	pki "gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/platform/transaction"
)

type LeafStatus struct{ Owner *pki.Materials }

func (a LeafStatus) ValidateLeafWithin(sc transaction.Scope, v cert.Version, managed bool) error {
	return a.Owner.ValidateWithin(sc, pki.LeafIdentity{IssuerKey: v.IssuerKeyFingerprint, Serial: v.Serial, DERDigest: v.LeafFingerprint, Managed: managed})
}
