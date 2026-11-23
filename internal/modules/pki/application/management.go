package application

import (
	"context"
	"gatebeam/internal/modules/pki/domain"
)

// IssuerReader is the P1 management capability: public metadata only. Future
// principal/revocation management must add its own transactional authority.
type IssuerReader interface {
	ReadIssuer(context.Context, domain.IssuerID) (domain.Issuer, error)
}
type Management struct{ reader IssuerReader }

func NewManagement(reader IssuerReader) *Management { return &Management{reader: reader} }
func (s *Management) Issuer(ctx context.Context, id domain.IssuerID) (domain.Issuer, error) {
	return s.reader.ReadIssuer(ctx, id)
}
