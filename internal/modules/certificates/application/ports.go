// Package application owns certificate management and current material contracts.
package application

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"time"
)

type ActorRef struct {
	UserID                       string
	AuthVersion                  int64
	CredentialKind, CredentialID string
}
type Spec = domain.Spec
type ProviderAccount = domain.ProviderAccount
type DNSCredential = domain.DNSCredential
type TrustBundle = domain.TrustBundle
type Version = domain.Version
type Resource struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Revision int64           `json:"revision"`
	Enabled  bool            `json:"enabled"`
	Body     json.RawMessage `json:"body"`
}

// Record is private adapter data, never a transport DTO. Secret is labelled age ciphertext.
type Record struct {
	Resource
	PEM, Secret []byte
}
type MaterialRef struct {
	ID, Kind string
	Revision int64
	Names    []string
	Purpose  string
}
type Material struct {
	Ref                                      MaterialRef
	Version                                  Version
	CertificatePEM, KeyPEM, TrustPEM, CRLPEM []byte
	OriginPullAuthorized                     bool
	Status                                   *StatusAttestation
}
type Materials struct {
	Generation string
	Items      []Material
}
type StatusAttestation struct {
	ResolverServers           []string
	UnknownResponderReady     bool
	Generation, ProfileDigest string
	ValidUntil                time.Time
	ResponderNames            []string
	CRLPEM                    []byte
}
type StoredVersion struct {
	Version
	CertificatePEM, EncryptedKey []byte
}
type Work struct {
	Spec        Record
	Account     Record
	Trust       Record
	Credentials []Record
	Token       string
	Attempt     domain.Attempt
}
type Repository interface {
	PreparationDue(transaction.Scope) ([]Resource, error)
	ClaimPreparation(transaction.Scope, Resource, string, time.Time) (domain.Attempt, error)
	FinishPreparation(transaction.Scope, Resource, string, domain.Attempt) error
	Status(transaction.Scope, string, int64, string) (StatusAttestation, error)
	SaveStatus(transaction.Scope, string, int64, StatusAttestation) error
	List(transaction.Scope, string) ([]Record, error)
	Enable(transaction.Scope, string, string, int64, bool) error
	ReadLock(transaction.Scope) error
	WriteLock(transaction.Scope) error
	Read(transaction.Scope, string, string, int64) (Record, error)
	Save(transaction.Scope, Record, int64) error
	Specs(transaction.Scope) ([]Record, error)
	Current(transaction.Scope, string, int64) (StoredVersion, error)
	Claim(transaction.Scope, string, int64, string, time.Time) (domain.Attempt, error)
	Commit(transaction.Scope, Work, StoredVersion) error
	Fail(transaction.Scope, Work, domain.Attempt) error
}
type Security interface {
	Within(context.Context, ActorRef, func(transaction.Scope) error) error
	RequireWithin(transaction.Scope, ActorRef, []string) error
}

// Graph freezes current draft AND published references before certificate locks.
type Graph interface{ GuardWithin(transaction.Scope) error }
type SecretSealer interface {
	Seal(string, []byte) ([]byte, error)
}
type Secrets interface {
	SecretSealer
	Open(string, []byte) ([]byte, error)
}
type Cryptography interface {
	Covers([]byte, []string) error
	NewAccountKey() ([]byte, error)
	Inspect(Spec, []byte, []byte, time.Time, []byte) (Version, error)
	InspectTrust(string, []byte, time.Time) ([]string, error)
	Digest([]byte) string
	NewID() (string, error)
}
type Issuance struct{ CertificatePEM, KeyPEM []byte }
type Issuer interface {
	Obtain(context.Context, Work) (Issuance, error)
}
type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type Events interface {
	EnqueueWithin(transaction.Scope, string, string, json.RawMessage) (string, error)
}

type Attestor interface {
	ProfileDigest(string) string
	Attest(context.Context, TrustBundle, []byte, time.Time) (StatusAttestation, error)
}

// ChallengeReceipt stores no token or key authorization; only the public TXT
// value and exact ownership proof needed for bounded, restart-safe cleanup.
type ChallengeReceipt struct {
	Owner, Binding, CredentialID                       string
	CredentialRevision                                 int64
	ZoneID, ZoneName, RecordID, Name, Content, Comment string
}
type PendingChallenge struct {
	Receipt    ChallengeReceipt
	Credential Record
}
type ChallengeJournal interface {
	Save(context.Context, ChallengeReceipt) error
	Complete(context.Context, string, string) error
	Pending(context.Context) ([]PendingChallenge, error)
}

// LeafStatus validates current owning PKI state; its lock lasts through Scope.
type LeafStatus interface {
	ValidateLeafWithin(transaction.Scope, Version, bool) error
}
