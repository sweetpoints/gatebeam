package application

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"sort"
	"time"
)

type Management struct {
	security                     Security
	graph                        Graph
	repo                         Repository
	crypto                       Cryptography
	leafSecrets, providerSecrets SecretSealer
	audit                        Audit
	now                          func() time.Time
}

func NewManagement(security Security, graph Graph, repo Repository, crypto Cryptography, leafSecrets, providerSecrets SecretSealer, audit Audit) *Management {
	return &Management{security, graph, repo, crypto, leafSecrets, providerSecrets, audit, time.Now}
}
func label(kind, id string, revision int64) string {
	b, _ := json.Marshal([]any{kind, id, revision})
	return "certificates/" + string(b)
}
func (m *Management) SaveSpec(ctx context.Context, a ActorRef, id string, expected int64, s Spec) (Resource, error) {
	if e := s.Validate(); e != nil {
		return Resource{}, e
	}
	b, _ := json.Marshal(s)
	return m.save(ctx, a, Record{Resource: Resource{ID: id, Kind: "spec", Enabled: true, Body: b}}, expected, nil)
}
func (m *Management) SaveAccount(ctx context.Context, a ActorRef, id string, expected int64, p ProviderAccount, eabHMAC []byte) (Resource, error) {
	if e := p.Validate(); e != nil {
		return Resource{}, e
	}
	if len(eabHMAC) > 4096 || (p.EABKeyID != "" && len(eabHMAC) == 0) {
		return Resource{}, domain.ErrInvalid
	}
	key, e := m.crypto.NewAccountKey()
	if e != nil {
		return Resource{}, e
	}
	defer clear(key)
	secret, _ := json.Marshal(struct{ Key, EAB []byte }{key, eabHMAC})
	defer clear(secret)
	b, _ := json.Marshal(p)
	return m.save(ctx, a, Record{Resource: Resource{ID: id, Kind: "account", Enabled: true, Body: b}}, expected, secret)
}
func (m *Management) SaveCredential(ctx context.Context, a ActorRef, id string, expected int64, c DNSCredential, token []byte) (Resource, error) {
	if c.Validate() != nil || len(token) < 1 || len(token) > 4096 {
		return Resource{}, domain.ErrInvalid
	}
	b, _ := json.Marshal(c)
	return m.save(ctx, a, Record{Resource: Resource{ID: id, Kind: "credential", Enabled: true, Body: b}}, expected, token)
}
func (m *Management) SaveTrust(ctx context.Context, a ActorRef, id string, expected int64, t TrustBundle, pem []byte) (Resource, error) {
	fingerprints, e := m.crypto.InspectTrust(t.Purpose, pem, m.now())
	if e != nil {
		return Resource{}, e
	}
	t.Fingerprints = fingerprints
	if e = t.Validate(); e != nil {
		return Resource{}, e
	}
	b, _ := json.Marshal(t)
	return m.save(ctx, a, Record{Resource: Resource{ID: id, Kind: "trust", Enabled: true, Body: b}, PEM: pem}, expected, nil)
}
func (m *Management) authorize(sc transaction.Scope, a ActorRef, kind, id string) error {
	ids := []string{id}
	if kind == "account" || kind == "credential" || kind == "trust" {
		specs, e := m.repo.Specs(sc)
		if e != nil {
			return e
		}
		for _, r := range specs {
			var spec Spec
			if json.Unmarshal(r.Body, &spec) != nil {
				return domain.ErrInvalid
			}
			used := spec.ProviderID == id || spec.TrustID == id
			for _, v := range spec.CredentialIDs {
				used = used || v == id
			}
			if used {
				ids = append(ids, r.ID)
			}
		}
	}
	sort.Strings(ids)
	return m.security.RequireWithin(sc, a, ids)
}
func (m *Management) save(ctx context.Context, a ActorRef, r Record, expected int64, plain []byte) (out Resource, err error) {
	if expected < 0 || (expected == 0 && r.ID != "") || (expected > 0 && r.ID == "") {
		return out, domain.ErrInvalid
	}
	if expected == 0 {
		r.ID, err = m.crypto.NewID()
		if err != nil {
			return out, err
		}
	}
	r.Revision = expected + 1
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = m.security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := m.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := m.repo.WriteLock(sc); e != nil {
			return e
		}
		if e := m.authorize(sc, a, r.Kind, r.ID); e != nil {
			return e
		}
		if r.Kind == "spec" {
			var spec Spec
			_ = json.Unmarshal(r.Body, &spec)
			for _, reference := range append([]string{spec.ProviderID, spec.TrustID}, spec.CredentialIDs...) {
				if reference != "" {
					kind := "credential"
					if reference == spec.ProviderID {
						kind = "account"
					}
					if reference == spec.TrustID {
						kind = "trust"
					}
					if e := m.authorize(sc, a, kind, reference); e != nil {
						return e
					}
				}
			}
			if spec.ProviderID != "" {
				account, e := m.repo.Read(sc, "account", spec.ProviderID, 0)
				if e != nil || !account.Enabled {
					return domain.ErrUnavailable
				}
				if ValidateEnrollment(spec, account) != nil {
					return domain.ErrInvalid
				}
			}
			for _, id := range spec.CredentialIDs {
				credential, e := m.repo.Read(sc, "credential", id, 0)
				if e != nil || !credential.Enabled {
					return domain.ErrUnavailable
				}
			}
			if spec.TrustID != "" {
				trust, e := m.repo.Read(sc, "trust", spec.TrustID, spec.TrustRevision)
				if e != nil || !trust.Enabled {
					return domain.ErrUnavailable
				}
			}
		}
		if len(plain) > 0 {
			var e error
			r.Secret, e = m.providerSecrets.Seal(label(r.Kind, r.ID, r.Revision), plain)
			if e != nil {
				return e
			}
		}
		if e := m.repo.Save(sc, r, expected); e != nil {
			return e
		}
		id, e := m.crypto.NewID()
		if e != nil {
			return e
		}
		payload, _ := json.Marshal(map[string]any{"resource_id": r.ID, "kind": r.Kind, "revision": r.Revision})
		if e = m.audit.Append(sc, audit.Event{ID: id, ActorID: a.UserID, Action: "certificates.resource.updated", Payload: payload}); e != nil {
			return e
		}
		out = r.Resource
		return nil
	})
	if err != nil {
		return Resource{}, err
	}
	return
}

func (m *Management) SetEnabled(ctx context.Context, a ActorRef, kind, id string, revision int64, enabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return m.security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := m.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := m.repo.WriteLock(sc); e != nil {
			return e
		}
		if e := m.authorize(sc, a, kind, id); e != nil {
			return e
		}
		if e := m.repo.Enable(sc, kind, id, revision, enabled); e != nil {
			return e
		}
		eventID, e := m.crypto.NewID()
		if e != nil {
			return e
		}
		body, _ := json.Marshal(map[string]any{"resource_id": id, "kind": kind, "enabled": enabled})
		return m.audit.Append(sc, audit.Event{ID: eventID, ActorID: a.UserID, Action: "certificates.resource.enabled", Payload: body})
	})
}
func (m *Management) Read(ctx context.Context, a ActorRef, kind, id string) (out Resource, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = m.security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := m.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := m.repo.ReadLock(sc); e != nil {
			return e
		}
		if e := m.authorize(sc, a, kind, id); e != nil {
			return e
		}
		r, e := m.repo.Read(sc, kind, id, 0)
		out = r.Resource
		return e
	})
	if err != nil {
		return Resource{}, err
	}
	return
}
