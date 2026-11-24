package status

import (
	"context"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
	"time"
)

// RootResponder is an offline-authorized status-only capability. It cannot
// issue certificates; its infrastructure owns standard CertID/CRL interpretation.
type RootResponder interface {
	MatchIssuer(CertID) error
	KnownIssuerID() domain.IssuerID
	Response(context.Context, CertID, []byte, time.Time) (RootResponse, error)
	RootList(context.Context) (RootCRL, error)
}
type RootCRL struct {
	RevokedSerials []string
	Issuer         domain.IssuerID
	Number         int64
	DER            []byte
}
type RootResponse struct {
	DER []byte
	CRL RootCRL
}
type RootRepository interface {
	AcceptRootCRL(transaction.Scope, RootCRL) error
	IssuerDER(transaction.Scope, domain.IssuerID) ([]byte, error)
}
type RootService struct {
	tx        transaction.Runner
	repo      RootRepository
	responder RootResponder
	now       func() time.Time
}

func NewRoot(tx transaction.Runner, repo RootRepository, responder RootResponder) *RootService {
	return &RootService{tx, repo, responder, time.Now}
}
func (s *RootService) OCSP(ctx context.Context, id CertID) ([]byte, error) {
	if e := s.responder.MatchIssuer(id); e != nil {
		return nil, e
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out []byte
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		der, e := s.repo.IssuerDER(sc, s.responder.KnownIssuerID())
		if e != nil {
			return e
		}
		response, e := s.responder.Response(ctx, id, der, s.now())
		if e != nil {
			return e
		}
		if e = s.repo.AcceptRootCRL(sc, response.CRL); e != nil {
			return e
		}
		out = response.DER
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}

type OCSPService interface {
	OCSP(context.Context, CertID) ([]byte, error)
}
type Responders struct{ Leaf, Root OCSPService }

func (s Responders) OCSP(ctx context.Context, id CertID) ([]byte, error) {
	b, e := s.Leaf.OCSP(ctx, id)
	if e == ErrUnknownIssuer && s.Root != nil {
		return s.Root.OCSP(ctx, id)
	}
	return b, e
}

func (s *RootService) ReadRootCRL(ctx context.Context) ([]byte, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out []byte
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		list, e := s.responder.RootList(ctx)
		if e != nil {
			return e
		}
		if e = s.repo.AcceptRootCRL(sc, list); e != nil {
			return e
		}
		out = list.DER
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
