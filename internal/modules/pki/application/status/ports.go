// Package status owns authoritative certificate status and permanent revocation.
package status

import (
	"context"
	"errors"
	management "gatebeam/internal/modules/pki/application"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

var ErrUnknownIssuer = errors.New("unknown certificate issuer")
var ErrDenied = errors.New("certificate revocation denied")

type ActorRef = management.ActorRef
type CertID struct {
	Hash              string
	NameHash, KeyHash []byte
	Serial            domain.Serial
}
type Record struct {
	State      domain.CertificateStatus
	Revocation domain.Revocation
}
type Owner struct {
	PrincipalID, AccountID, Directory, OrderID string
	Names                                      []string
}
type Repository interface {
	Owner(transaction.Scope, domain.IssuerID, domain.Serial) (Owner, error)
	Principal(transaction.Scope, string) (domain.Principal, error)
	Account(transaction.Scope, string, string) (domain.Account, error)
	Certificate(transaction.Scope, string) (domain.IssuedCertificate, error)
	AuthorizedNames(transaction.Scope, string, time.Time) ([]string, error)
	Status(transaction.Scope, domain.IssuerID, domain.Serial) (Record, error)
	Revoke(transaction.Scope, domain.IssuerID, domain.Revocation) error
	ReserveResponder(transaction.Scope, domain.IssuerID, domain.Serial, []byte) error
	CRLSnapshot(transaction.Scope, domain.IssuerID) (int64, []domain.Revocation, error)
}
type SignedResponse struct {
	DER, CredentialDER []byte
	CredentialSerial   domain.Serial
}
type Signer interface {
	MatchIssuer(CertID) (domain.IssuerID, error)
	CertificateID([]byte) (domain.IssuerID, domain.Serial, error)
	MatchCertificateKey([]byte, []byte) bool
	SignOCSP(CertID, Record, time.Time) (SignedResponse, error)
	SignCRL(domain.IssuerID, int64, []domain.Revocation, time.Time) ([]byte, error)
}
type Service struct {
	tx     transaction.Runner
	repo   Repository
	signer Signer
	now    func() time.Time
}

func New(tx transaction.Runner, repo Repository, signer Signer, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{tx, repo, signer, now}
}
func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}
func (s *Service) OCSP(ctx context.Context, id CertID) ([]byte, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	issuer, e := s.signer.MatchIssuer(id)
	if e != nil {
		return nil, e
	}
	var out []byte
	e = s.tx.Within(ctx, func(sc transaction.Scope) error {
		r, e := s.repo.Status(sc, issuer, id.Serial)
		if e != nil {
			return e
		}
		signed, e := s.signer.SignOCSP(id, r, s.now())
		if e != nil {
			return e
		}
		if e = s.repo.ReserveResponder(sc, issuer, signed.CredentialSerial, signed.CredentialDER); e != nil {
			return e
		}
		out = signed.DER
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Service) CRL(ctx context.Context, id domain.IssuerID) ([]byte, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out []byte
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		n, rows, e := s.repo.CRLSnapshot(sc, id)
		if e != nil {
			return e
		}
		out, e = s.signer.SignCRL(id, n, rows, s.now())
		return e
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
