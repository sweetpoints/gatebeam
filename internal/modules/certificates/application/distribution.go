package application

import (
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/transaction"
	"regexp"
	"time"
)

// NodeRef is certificate-owner identity data. Integration maps deployment's
// independently owned incarnation value into this contract.
type NodeRef struct {
	ID    string
	Epoch uint64
}
type RecipientBinding struct {
	Node                 NodeRef
	Recipient, VersionID string
}
type DistributionRepository interface {
	VersionWithin(transaction.Scope, string) (StoredVersion, error)
	EnvelopeWithin(transaction.Scope, RecipientBinding) ([]byte, error)
	SaveEnvelopeWithin(transaction.Scope, RecipientBinding, []byte) error
}
type DistributionAuthority interface {
	TargetWithin(transaction.Scope, RecipientBinding) error
	CallerWithin(transaction.Scope, NodeRef) error
}
type RecipientSealer interface {
	SealRecipient(recipient, label string, plain []byte) ([]byte, error)
}
type Distribution struct {
	status    LeafStatus
	repo      DistributionRepository
	authority DistributionAuthority
	owner     Secrets
	sealer    RecipientSealer
	now       func() time.Time
}

func NewDistribution(repo DistributionRepository, authority DistributionAuthority, owner Secrets, sealer RecipientSealer, now func() time.Time) *Distribution {
	return &Distribution{repo: repo, authority: authority, owner: owner, sealer: sealer, now: now}
}

var materialUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validBinding(b RecipientBinding) bool {
	return materialUUID.MatchString(b.Node.ID) && b.Node.Epoch > 0 && b.Node.Epoch <= 1<<63-1 && materialUUID.MatchString(b.VersionID) && len(b.Recipient) > 0 && len(b.Recipient) <= 128
}
func (d *Distribution) available(sc transaction.Scope, id string) (StoredVersion, error) {
	v, e := d.repo.VersionWithin(sc, id)
	if e != nil {
		return StoredVersion{}, e
	}
	if d.status == nil {
		return StoredVersion{}, domain.ErrUnavailable
	}
	managed := v.EnrollmentProvider == "internal-client" || v.EnrollmentProvider == "internal-server"
	if e := d.status.ValidateLeafWithin(sc, v, managed); e != nil {
		return StoredVersion{}, e
	}
	if !v.Usable(d.now()) {
		return StoredVersion{}, domain.ErrUnavailable
	}
	return v, nil
}

// EnvelopeWithin authenticates the live DB connection as the registered node.
// The binding supplied by a caller can never authorize its own recipient.
func (d *Distribution) EnvelopeWithin(sc transaction.Scope, b RecipientBinding) ([]byte, error) {
	if !validBinding(b) || d.authority == nil {
		return nil, domain.ErrDenied
	}
	if e := d.authority.CallerWithin(sc, b.Node); e != nil {
		return nil, e
	}
	if e := d.authority.TargetWithin(sc, b); e != nil {
		return nil, e
	}
	if _, e := d.available(sc, b.VersionID); e != nil {
		return nil, e
	}
	return d.repo.EnvelopeWithin(sc, b)
}

// RewrapWithin preserves immutable certificate/version data. Only a process
// holding the original leaf identity can open the original labelled material;
// issuer workers retain their existing seal-only capability.
func (d *Distribution) RewrapWithin(sc transaction.Scope, id string, bindings []RecipientBinding) error {
	if !materialUUID.MatchString(id) || len(bindings) < 1 || len(bindings) > 32 || d.owner == nil || d.authority == nil || d.sealer == nil {
		return domain.ErrDenied
	}
	for _, b := range bindings {
		if !validBinding(b) || b.VersionID != id {
			return domain.ErrInvalid
		}
		if e := d.authority.TargetWithin(sc, b); e != nil {
			return e
		}
	}
	v, e := d.available(sc, id)
	if e != nil {
		return e
	}
	plain, e := d.owner.Open("certificates/version/"+id, v.EncryptedKey)
	if e != nil {
		return domain.ErrDenied
	}
	defer clear(plain)
	for _, b := range bindings {
		ciphertext, e := d.sealer.SealRecipient(b.Recipient, "certificates/version/"+id, plain)
		if e != nil {
			return e
		}
		if e = d.repo.SaveEnvelopeWithin(sc, b, ciphertext); e != nil {
			return e
		}
	}
	return nil
}

func (d *Distribution) SetLeafStatus(status LeafStatus) { d.status = status }
