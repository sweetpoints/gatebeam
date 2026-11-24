package acme

import (
	"context"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
)

func (s *OrderService) Finalize(ctx context.Context, ref AccountRef, id string, csr []byte) (domain.Order, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out domain.Order
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		o, _, p, e := s.load(sc, ref, id)
		if e != nil {
			return e
		}
		// Retry returns exactly the previously committed order after current authority.
		if o.Status == "valid" {
			if _, e = s.repo.Certificate(sc, o.ID); e != nil {
				return e
			}
			out = o
			return nil
		}
		if o.Ready(s.now()) != nil || s.signer == nil {
			return ErrOrderNotReady
		}
		policy, e := domain.NewPolicy(p.Names, p.Usage)
		if e != nil {
			return ErrDenied
		}
		issuer, serial, e := s.signer.NewSerial()
		if e != nil {
			return e
		}
		if e = s.repo.ReserveSerial(sc, issuer, serial); e != nil {
			return e
		}
		cert, e := s.signer.Sign(csr, policy, o.Names, serial, s.now())
		if e != nil {
			return e
		}
		if cert.IssuerID != issuer || cert.Serial != serial || len(cert.DER) == 0 {
			return ErrBadCSR
		}
		cert.OrderID = o.ID
		if e = s.repo.InsertCertificate(sc, cert); e != nil {
			return e
		}
		rev := o.Revision
		if e = o.Complete(s.now()); e != nil {
			return ErrOrderNotReady
		}
		if e = s.repo.SaveOrder(sc, o, rev); e != nil {
			return e
		}
		out = o
		return nil
	})
	if e != nil {
		return domain.Order{}, e
	}
	return out, nil
}
func (s *OrderService) Certificate(ctx context.Context, ref AccountRef, id string) (domain.IssuedCertificate, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out domain.IssuedCertificate
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		o, _, _, e := s.load(sc, ref, id)
		if e != nil {
			return e
		}
		if o.Status != "valid" {
			return ErrOrderNotReady
		}
		out, e = s.repo.Certificate(sc, o.ID)
		return e
	})
	if e != nil {
		return domain.IssuedCertificate{}, e
	}
	return out, nil
}
