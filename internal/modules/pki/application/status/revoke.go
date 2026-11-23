package status

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	management "gatebeam/internal/modules/pki/application"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"slices"
	"time"
)

// Management has no signing capability, private-key loader or crypto adapter.
type Management struct {
	security management.SecurityAction
	repo     Repository
	audit    management.AuditWriter
	random   management.GrantRandom
	now      func() time.Time
}

func NewManagement(security management.SecurityAction, repo Repository, audit management.AuditWriter, random management.GrantRandom, now func() time.Time) *Management {
	if now == nil {
		now = time.Now
	}
	return &Management{security, repo, audit, random, now}
}
func (s *Management) Revoke(ctx context.Context, actor ActorRef, issuerID, serial string, reason int) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return s.security.Within(ctx, actor, func(sc transaction.Scope) error {
		owner, e := s.repo.Owner(sc, domain.IssuerID(issuerID), domain.Serial(serial))
		if e != nil {
			return e
		}
		if _, e = s.repo.Principal(sc, owner.PrincipalID); e != nil {
			return e
		}
		rev, e := revokeWithin(sc, s.repo, domain.IssuerID(issuerID), domain.Serial(serial), reason, s.now())
		if e != nil {
			return e
		}
		id, e := s.random.Random()
		if e != nil {
			return e
		}
		payload, _ := json.Marshal(map[string]any{"issuer_id": issuerID, "serial": serial, "reason": rev.Reason})
		return s.audit.Append(sc, audit.Event{ID: id, ActorID: actor.UserID, Action: "pki.certificate.revoked", Payload: payload})
	})
}
func revokeWithin(sc transaction.Scope, repo Repository, issuer domain.IssuerID, serial domain.Serial, reason int, now time.Time) (domain.Revocation, error) {
	r, e := domain.NewRevocation(serial, reason, now)
	if e != nil {
		return r, e
	}
	old, e := repo.Status(sc, issuer, serial)
	if e != nil {
		return r, e
	}
	if old.State == domain.StatusUnknown {
		return r, ErrDenied
	}
	if old.State == domain.StatusRevoked {
		return r, domain.ErrAlreadyRevoked
	}
	return r, repo.Revoke(sc, issuer, r)
}

type Request struct {
	Directory, AccountID, Thumbprint string
	Certificate, Key                 []byte
	Reason                           int
}

// RevokeCertificate is RFC8555 authorization: either a verified certificate-key
// proof or a current valid account with authority for all certificate names.
// Transport verifies JWS/nonce; this transaction rechecks current account keys.
func (s *Service) RevokeCertificate(ctx context.Context, in Request) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	issuer, serial, e := s.signer.CertificateID(in.Certificate)
	if e != nil {
		return ErrDenied
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		owner, e := s.repo.Owner(sc, issuer, serial)
		if e != nil {
			return e
		}
		if owner.Directory != in.Directory {
			return ErrDenied
		}
		ids := []string{owner.PrincipalID}
		var account domain.Account
		if in.AccountID != "" {
			account, e = s.repo.Account(sc, in.Directory, in.AccountID)
			if e != nil {
				return ErrDenied
			}
			ids = append(ids, account.PrincipalID)
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		principals := map[string]domain.Principal{}
		for _, id := range ids {
			p, e := s.repo.Principal(sc, id)
			if e != nil {
				return e
			}
			principals[id] = p
		}
		cert, e := s.repo.Certificate(sc, owner.OrderID)
		if e != nil {
			return e
		}
		if !bytes.Equal(cert.DER, in.Certificate) {
			return ErrDenied
		}
		if in.AccountID == "" {
			if !s.signer.MatchCertificateKey(cert.DER, in.Key) {
				return ErrDenied
			}
		} else {
			current, e := s.repo.Account(sc, in.Directory, in.AccountID)
			if e != nil {
				return ErrDenied
			}
			p := principals[current.PrincipalID]
			if current.Status == "deactivated" {
				return errors.Join(ErrDenied, domain.ErrAccountDeactivated)
			}
			if current.Status != "valid" || current.Thumbprint != in.Thumbprint || p.Authorize(in.Directory, s.now()) != nil {
				return ErrDenied
			}
			policy, e := domain.NewPolicy(p.Names, p.Usage)
			if e != nil || policy.Authorize(owner.Names) != nil {
				return ErrDenied
			}
			if current.ID != owner.AccountID {
				authorized, e := s.repo.AuthorizedNames(sc, current.ID, s.now())
				if e != nil {
					return e
				}
				for _, name := range owner.Names {
					if !slices.Contains(authorized, name) {
						return ErrDenied
					}
				}
			}
		}
		_, e = revokeWithin(sc, s.repo, issuer, serial, in.Reason, s.now())
		return e
	})
}
