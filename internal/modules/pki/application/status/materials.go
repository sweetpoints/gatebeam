package status

import "gatebeam/internal/platform/transaction"

// LeafIdentity binds the actual verified issuer key and immutable leaf DER.
// Imported external CAs have a separate policy; known local keys never bypass it.
type LeafIdentity struct {
	IssuerKey, Serial, DERDigest string
	Managed                      bool
}
type LeafState struct{ Unclassified, KnownIssuer, Good, Unsafe bool }
type LeafRepository interface {
	ReadLeafWithin(transaction.Scope, LeafIdentity) (LeafState, error)
}
type Materials struct{ repo LeafRepository }

func NewMaterials(repo LeafRepository) *Materials { return &Materials{repo: repo} }
func (s *Materials) ValidateWithin(sc transaction.Scope, leaf LeafIdentity) error {
	if len(leaf.IssuerKey) != 64 || len(leaf.DERDigest) != 64 || len(leaf.Serial) != 40 {
		return ErrDenied
	}
	state, err := s.repo.ReadLeafWithin(sc, leaf)
	if err != nil {
		return err
	}
	if state.Unclassified || state.Unsafe || ((state.KnownIssuer || leaf.Managed) && !state.Good) {
		return ErrDenied
	}
	return nil
}
