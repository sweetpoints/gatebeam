package acme

import (
	"context"
	"errors"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
	"time"
)

var ErrOrderNotReady = errors.New("order is not ready")
var ErrBadCSR = errors.New("CSR rejected")
var ErrOrderNotFound = errors.New("order does not exist")

type OrderRepository interface {
	Account(transaction.Scope, string, string) (domain.Account, error)
	Principal(transaction.Scope, string) (domain.Principal, error)
	InsertOrder(transaction.Scope, domain.Order) error
	Order(transaction.Scope, string, string) (domain.Order, error)
	SaveOrder(transaction.Scope, domain.Order, int64) error
	Orders(transaction.Scope, string, string) ([]string, error)
	ReserveSerial(transaction.Scope, domain.IssuerID, domain.Serial) error
	InsertCertificate(transaction.Scope, domain.IssuedCertificate) error
	Certificate(transaction.Scope, string) (domain.IssuedCertificate, error)
}
type HTTP01 interface {
	Validate(context.Context, string, string, string) error
}
type Signer interface {
	NewSerial() (domain.IssuerID, domain.Serial, error)
	Sign([]byte, domain.Policy, []string, domain.Serial, time.Time) (domain.IssuedCertificate, error)
}
type OrderService struct {
	tx        transaction.Runner
	repo      OrderRepository
	random    Random
	validator HTTP01
	signer    Signer
	now       Clock
}

func NewOrders(tx transaction.Runner, r OrderRepository, random Random, v HTTP01, signer Signer, now Clock) *OrderService {
	if now == nil {
		now = time.Now
	}
	return &OrderService{tx, r, random, v, signer, now}
}

type AccountRef struct{ Directory, ID, Thumbprint string }

// current always locks principal before reading current account state. Key bytes
// used earlier for JWS verification are not a durable authorization decision.
func (s *OrderService) current(sc transaction.Scope, ref AccountRef) (domain.Account, domain.Principal, error) {
	a, e := s.repo.Account(sc, ref.Directory, ref.ID)
	if e != nil {
		return a, domain.Principal{}, e
	}
	p, e := s.repo.Principal(sc, a.PrincipalID)
	if e != nil {
		return a, p, e
	}
	a, e = s.repo.Account(sc, ref.Directory, ref.ID)
	if e != nil {
		return a, p, e
	}
	if a.Status == "deactivated" {
		return a, p, errors.Join(ErrDenied, domain.ErrAccountDeactivated)
	}
	if p.Authorize(ref.Directory, s.now()) != nil || a.Status != "valid" || a.Thumbprint != ref.Thumbprint {
		return a, p, ErrDenied
	}
	return a, p, nil
}
func (s *OrderService) load(sc transaction.Scope, ref AccountRef, id string) (domain.Order, domain.Account, domain.Principal, error) {
	a, p, e := s.current(sc, ref)
	if e != nil {
		return domain.Order{}, a, p, e
	}
	o, e := s.repo.Order(sc, id, a.ID)
	if errors.Is(e, ErrNotFound) {
		e = ErrOrderNotFound
	}
	if e != nil {
		return o, a, p, e
	}
	if o.Authorize(p, s.now()) != nil {
		return o, a, p, ErrDenied
	}
	return o, a, p, nil
}
func (s *OrderService) NewOrder(ctx context.Context, ref AccountRef, names []string) (domain.Order, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out domain.Order
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		a, p, e := s.current(sc, ref)
		if e != nil {
			return e
		}
		policy, e := domain.NewPolicy(p.Names, p.Usage)
		if e != nil || policy.Authorize(names) != nil {
			return ErrDenied
		}
		id, e := s.random.Random()
		if e != nil {
			return e
		}
		ch := make([]domain.Challenge, len(names))
		for i, n := range names {
			cid, e := s.random.Random()
			if e != nil {
				return e
			}
			token, e := s.random.Random()
			if e != nil {
				return e
			}
			ch[i] = domain.Challenge{ID: cid, Name: n, Token: token, Status: "pending"}
		}
		o, e := domain.NewOrder(id, a.ID, p, names, ch, s.now())
		if e != nil {
			return e
		}
		if e = s.repo.InsertOrder(sc, o); e != nil {
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
func (s *OrderService) Order(ctx context.Context, ref AccountRef, id string) (domain.Order, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out domain.Order
	e := s.tx.Within(ctx, func(sc transaction.Scope) error { var e error; out, _, _, e = s.load(sc, ref, id); return e })
	if e != nil {
		return domain.Order{}, e
	}
	if out.Status != "valid" && !s.now().Before(out.Expires) {
		out.Status = "invalid"
	}
	return out, nil
}
func (s *OrderService) Orders(ctx context.Context, ref AccountRef, after string) ([]string, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out []string
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		a, _, e := s.current(sc, ref)
		if e != nil {
			return e
		}
		out, e = s.repo.Orders(sc, a.ID, after)
		return e
	})
	return out, e
}
