package application

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/audit"
	"gatebeam-ca/internal/platform/transaction"
	"time"
)

var ErrGrantDenied = errors.New("PKI management denied")

type ActorRef struct {
	UserID                       string
	AuthVersion                  int64
	CredentialKind, CredentialID string
}
type GrantSpec struct {
	Names     []string     `json:"names"`
	Purpose   domain.Usage `json:"purpose"`
	Directory string       `json:"directory"`
	Expires   time.Time    `json:"expires"`
}
type Grant struct {
	ID        string           `json:"id"`
	Principal domain.Principal `json:"principal"`
}
type EABCredentials struct {
	KeyID     string    `json:"kid"`
	HMAC      string    `json:"hmac"`
	Directory string    `json:"directory"`
	Expires   time.Time `json:"expires"`
}

// SecurityAction validates the authenticated administrator inside the same
// transaction as the operation and its audit record.
type SecurityAction interface {
	Within(context.Context, ActorRef, func(transaction.Scope) error) error
}
type GrantRepository interface {
	InsertGrant(transaction.Scope, Grant) error
	GrantPrincipal(transaction.Scope, string) (string, error)
	Principal(transaction.Scope, string) (domain.Principal, error)
	ReplaceBinding(transaction.Scope, string, domain.Binding) error
	DisablePrincipal(transaction.Scope, string) error
}
type SecretSealer interface {
	Seal(string, []byte) ([]byte, error)
}
type GrantRandom interface{ Random() (string, error) }
type AuditWriter interface {
	Append(transaction.Scope, audit.Event) error
}
type GrantService struct {
	security SecurityAction
	repo     GrantRepository
	secrets  SecretSealer
	random   GrantRandom
	audit    AuditWriter
	policies map[string]domain.Policy
	now      func() time.Time
}

func NewGrantService(security SecurityAction, repo GrantRepository, secrets SecretSealer, random GrantRandom, audit AuditWriter, policies map[string]domain.Policy, now func() time.Time) *GrantService {
	if now == nil {
		now = time.Now
	}
	return &GrantService{security, repo, secrets, random, audit, policies, now}
}
func (s *GrantService) event(sc transaction.Scope, actor ActorRef, action, id string) error {
	eventID, e := s.random.Random()
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(map[string]string{"resource_id": id})
	return s.audit.Append(sc, audit.Event{ID: eventID, ActorID: actor.UserID, Action: action, Payload: payload})
}
func (s *GrantService) Authorize(ctx context.Context, actor ActorRef, spec GrantSpec) (Grant, error) {
	var out Grant
	e := s.security.Within(ctx, actor, func(sc transaction.Scope) error {
		id, e := s.random.Random()
		if e != nil {
			return e
		}
		pid, e := s.random.Random()
		if e != nil {
			return e
		}
		p := domain.Principal{ID: pid, Names: append([]string(nil), spec.Names...), Usage: spec.Purpose, Directory: spec.Directory, Expires: spec.Expires}
		policy, ok := s.policies[spec.Directory]
		if !ok || policy.Usage() != spec.Purpose || policy.Authorize(spec.Names) != nil || p.Validate(s.now()) != nil {
			return domain.ErrPolicy
		}
		out = Grant{ID: id, Principal: p}
		if e = s.repo.InsertGrant(sc, out); e != nil {
			return e
		}
		return s.event(sc, actor, "pki.grant.authorized", id)
	})
	if e != nil {
		return Grant{}, e
	}
	return out, nil
}
func (s *GrantService) IssueEAB(ctx context.Context, actor ActorRef, grantID string) (EABCredentials, error) {
	var out EABCredentials
	e := s.security.Within(ctx, actor, func(sc transaction.Scope) error {
		pid, e := s.repo.GrantPrincipal(sc, grantID)
		if e != nil {
			return e
		}
		p, e := s.repo.Principal(sc, pid)
		if e != nil {
			return e
		}
		if p.Authorize(p.Directory, s.now()) != nil {
			return ErrGrantDenied
		}
		id, e := s.random.Random()
		if e != nil {
			return e
		}
		raw, e := s.random.Random()
		if e != nil {
			return e
		}
		secret, e := base64.RawURLEncoding.DecodeString(raw)
		if e != nil {
			return e
		}
		defer clear(secret)
		cipher, e := s.secrets.Seal("pki/eab/"+id, secret)
		if e != nil {
			return e
		}
		expires := s.now().Add(15 * time.Minute)
		if p.Expires.Before(expires) {
			expires = p.Expires
		}
		if e = s.repo.ReplaceBinding(sc, grantID, domain.Binding{ID: id, PrincipalID: pid, Cipher: cipher, Expires: expires}); e != nil {
			return e
		}
		if e = s.event(sc, actor, "pki.eab.issued", id); e != nil {
			return e
		}
		out = EABCredentials{KeyID: id, HMAC: raw, Directory: p.Directory, Expires: expires}
		return nil
	})
	if e != nil {
		return EABCredentials{}, e
	}
	return out, nil
}
func (s *GrantService) DisablePrincipal(ctx context.Context, actor ActorRef, id string) error {
	return s.security.Within(ctx, actor, func(sc transaction.Scope) error {
		if _, e := s.repo.Principal(sc, id); e != nil {
			return e
		}
		if e := s.repo.DisablePrincipal(sc, id); e != nil {
			return e
		}
		return s.event(sc, actor, "pki.principal.disabled", id)
	})
}
