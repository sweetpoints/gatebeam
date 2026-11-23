package acme

import (
	"context"
	"errors"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Service struct {
	tx      transaction.Runner
	repo    Repository
	random  Random
	secrets Opener
	now     Clock
}

func New(tx transaction.Runner, r Repository, random Random, secrets Opener, now Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{tx, r, random, secrets, now}
}
func (s *Service) Lookup(ctx context.Context, directory, id, thumb string) (domain.Account, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var a domain.Account
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		var e error
		if id != "" {
			a, e = s.repo.Account(sc, directory, id)
		} else {
			a, e = s.repo.AccountByKey(sc, directory, thumb)
		}
		return e
	})
	return a, e
}

type Registration struct {
	Directory    string
	Key          PublicKey
	BindingID    string
	Proof        BindingProof
	OnlyExisting bool
	Contacts     []string
}

func (s *Service) Register(ctx context.Context, in Registration) (domain.Account, bool, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out domain.Account
	created := false
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		a, e := s.repo.AccountByKey(sc, in.Directory, in.Key.Thumbprint)
		if e == nil {
			p, e := s.repo.Principal(sc, a.PrincipalID)
			if e != nil {
				return e
			}
			a, e = s.repo.Account(sc, in.Directory, a.ID)
			if e != nil {
				return e
			}
			if a.Status == "deactivated" {
				return errors.Join(ErrDenied, domain.ErrAccountDeactivated)
			}
			if p.Authorize(in.Directory, s.now()) != nil || a.Status != "valid" || a.Thumbprint != in.Key.Thumbprint {
				return ErrDenied
			}
			out = a
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		if in.OnlyExisting {
			return ErrNotFound
		}
		if in.BindingID == "" || in.Proof == nil {
			return ErrEABRequired
		}
		pid, e := s.repo.BindingPrincipal(sc, in.BindingID)
		if e != nil {
			return ErrDenied
		}
		p, e := s.repo.Principal(sc, pid)
		if e != nil {
			return e
		}
		b, e := s.repo.Binding(sc, in.BindingID)
		if e != nil {
			return ErrDenied
		}
		if b.Consume(p, in.Directory, s.now()) != nil {
			return ErrDenied
		}
		secret, e := s.secrets.Open("pki/eab/"+b.ID, b.Cipher)
		if e != nil {
			return ErrDenied
		}
		defer clear(secret)
		if in.Proof.VerifyBinding(secret, in.Key) != nil {
			return ErrDenied
		}
		id, e := s.random.Random()
		if e != nil {
			return e
		}
		a = domain.Account{ID: id, PrincipalID: p.ID, Directory: in.Directory, Thumbprint: in.Key.Thumbprint, Key: in.Key.Encoded, Status: "valid", Contacts: in.Contacts}
		if e = s.repo.InsertAccount(sc, a); e != nil {
			return e
		}
		if e = s.repo.ConsumeBinding(sc, b.ID); e != nil {
			return e
		}
		out = a
		created = true
		return nil
	})
	if e != nil {
		return domain.Account{}, false, e
	}
	return out, created, nil
}

// Current re-reads the key and principal while holding the principal lock. A
// key read to verify the incoming JWS is never an authorization snapshot.
func (s *Service) Current(ctx context.Context, directory, id, thumb string, contacts []string, deactivate bool) (domain.Account, error) {
	if contacts == nil && !deactivate {
		// POST-as-GET and existing-account recovery still reauthorize under the
		// principal lock, but must not write or invalidate an in-flight proof.
		return s.change(ctx, directory, id, thumb, nil)
	}
	return s.change(ctx, directory, id, thumb, func(a *domain.Account) error {
		if deactivate {
			return a.Deactivate()
		}
		if contacts != nil {
			a.Contacts = contacts
		}
		return nil
	})
}
func (s *Service) ChangeKey(ctx context.Context, directory, id, old string, next PublicKey) (domain.Account, error) {
	return s.change(ctx, directory, id, old, func(a *domain.Account) error { return a.ChangeKey(old, next.Thumbprint, next.Encoded) })
}
func (s *Service) change(ctx context.Context, directory, id, thumb string, fn func(*domain.Account) error) (domain.Account, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var out domain.Account
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		a, e := s.repo.Account(sc, directory, id)
		if e != nil {
			return e
		}
		p, e := s.repo.Principal(sc, a.PrincipalID)
		if e != nil {
			return e
		}
		a, e = s.repo.Account(sc, directory, id)
		if e != nil {
			return e
		}
		if a.Status == "deactivated" {
			return errors.Join(ErrDenied, domain.ErrAccountDeactivated)
		}
		if p.Authorize(directory, s.now()) != nil || a.Status != "valid" || a.Thumbprint != thumb {
			return ErrDenied
		}
		if fn != nil {
			if e = fn(&a); e != nil {
				return ErrDenied
			}
			if e = s.repo.SaveAccount(sc, a); e != nil {
				return e
			}
		}
		out = a
		return nil
	})
	if e != nil {
		return domain.Account{}, e
	}
	return out, nil
}
