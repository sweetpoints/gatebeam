package application

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"sort"
	"time"
)

type Service struct {
	distribution *Distribution
	node         NodeRef
	recipient    string
	leafStatus   LeafStatus
	status       Attestor
	tx           transaction.Runner
	repo         Repository
	graph        Graph
	crypto       Cryptography
	secrets      Secrets
	issuer       Issuer
	events       Events
	management   *Management
	now          func() time.Time
}

func New(tx transaction.Runner, repo Repository, graph Graph, crypto Cryptography, secrets Secrets, issuer Issuer, events Events, m ...*Management) *Service {
	s := &Service{tx: tx, repo: repo, graph: graph, crypto: crypto, secrets: secrets, issuer: issuer, events: events, now: time.Now}
	if len(m) > 0 {
		s.management = m[0]
	}
	return s
}
func (s *Service) SetLeafStatus(status LeafStatus) {
	s.leafStatus = status
	if s.distribution != nil {
		s.distribution.SetLeafStatus(status)
	}
}

func (s *Service) Ensure(ctx context.Context, id string) (Version, error) {
	return s.ensure(ctx, id, 0, false)
}
func (s *Service) Renew(ctx context.Context, id string) (Version, error) {
	return s.ensure(ctx, id, 0, true)
}

// RenewRevision is a worker-only forced retry for one immutable revision. It
// retains the same spec-wide lease, backoff and final resource rechecks; no
// management transport exposes this capability.
func (s *Service) RenewRevision(ctx context.Context, id string, revision int64) (Version, error) {
	if revision < 1 {
		return Version{}, domain.ErrInvalid
	}
	return s.ensure(ctx, id, revision, true)
}

// EnsureRevision is used only for current published references, independent of drafts.
func (s *Service) EnsureRevision(ctx context.Context, id string, revision int64) (Version, error) {
	return s.ensure(ctx, id, revision, false)
}
func (s *Service) work(sc transaction.Scope, id string, revision int64) (w Work, err error) {
	w.Spec, err = s.repo.Read(sc, "spec", id, revision)
	if err != nil {
		return
	}
	if !w.Spec.Enabled {
		return w, domain.ErrUnavailable
	}
	var spec Spec
	if json.Unmarshal(w.Spec.Body, &spec) != nil || spec.Validate() != nil {
		return w, domain.ErrInvalid
	}
	if spec.TrustID != "" {
		trust, e := s.repo.Read(sc, "trust", spec.TrustID, spec.TrustRevision)
		w.Trust = trust
		if e != nil || !trust.Enabled {
			return w, domain.ErrUnavailable
		}
	}
	if !spec.Automatic() {
		return w, domain.ErrUnavailable
	}
	w.Account, err = s.repo.Read(sc, "account", spec.ProviderID, 0)
	if err != nil || !w.Account.Enabled {
		return w, domain.ErrUnavailable
	}
	if e := ValidateEnrollment(spec, w.Account); e != nil {
		return w, e
	}
	for _, id := range spec.CredentialIDs {
		v, e := s.repo.Read(sc, "credential", id, 0)
		if e != nil || !v.Enabled {
			return w, domain.ErrUnavailable
		}
		w.Credentials = append(w.Credentials, v)
	}
	return
}
func (s *Service) ensure(ctx context.Context, id string, revision int64, force bool) (out Version, err error) {
	if s.issuer == nil {
		return Version{}, domain.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var w Work
	claimed := false
	err = s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.WriteLock(sc); e != nil {
			return e
		}
		r, e := s.repo.Read(sc, "spec", id, revision)
		if e != nil || !r.Enabled {
			return domain.ErrUnavailable
		}
		var spec Spec
		if json.Unmarshal(r.Body, &spec) != nil || spec.Validate() != nil {
			return domain.ErrInvalid
		}
		current, e := s.repo.Current(sc, id, r.Revision)
		if e == nil && current.Usable(s.now()) && current.IssuerKeyFingerprint != "" && (spec.Method == "import" || current.EnrollmentProvider != "") && !force && (spec.Method == "import" || s.now().Before(current.NotAfter.Add(-current.NotAfter.Sub(current.NotBefore)/3))) {
			out = current.Version
			return nil
		}
		if e != nil && !errors.Is(e, domain.ErrNotFound) {
			return e
		}
		w, e = s.work(sc, id, r.Revision)
		if e != nil {
			return e
		}
		w.Token, e = s.crypto.NewID()
		if e != nil {
			return e
		}
		w.Attempt, e = s.repo.Claim(sc, id, w.Spec.Revision, w.Token, s.now().Add(2*time.Minute))
		claimed = e == nil
		return e
	})
	if err != nil || !claimed {
		return out, err
	}
	issued, e := s.issuer.Obtain(ctx, w)
	if e == nil {
		var spec Spec
		_ = json.Unmarshal(w.Spec.Body, &spec)
		out, e = s.crypto.Inspect(spec, issued.CertificatePEM, issued.KeyPEM, s.now(), w.Trust.PEM)
		var provider ProviderAccount
		if json.Unmarshal(w.Account.Body, &provider) != nil || provider.Validate() != nil {
			e = domain.ErrUnavailable
		}
		out.EnrollmentProvider = provider.Provider
	}
	defer clear(issued.KeyPEM)
	if e == nil {
		out.ID, e = s.crypto.NewID()
		out.SpecID = w.Spec.ID
		out.SpecRevision = w.Spec.Revision
		out.PrivateMaterialRef = out.ID
	}
	var cipher []byte
	if e == nil {
		cipher, e = s.secrets.Seal("certificates/version/"+out.ID, issued.KeyPEM)
	}
	if e == nil {
		e = s.tx.Within(ctx, func(sc transaction.Scope) error {
			if e := s.graph.GuardWithin(sc); e != nil {
				return e
			}
			if e := s.repo.WriteLock(sc); e != nil {
				return e
			}
			fresh, e := s.work(sc, w.Spec.ID, w.Spec.Revision)
			if e != nil {
				return e
			}
			if fresh.Account.Revision != w.Account.Revision || len(fresh.Credentials) != len(w.Credentials) {
				return domain.ErrConflict
			}
			for i, v := range fresh.Credentials {
				if v.ID != w.Credentials[i].ID || v.Revision != w.Credentials[i].Revision {
					return domain.ErrConflict
				}
			}
			if e = s.repo.Commit(sc, w, StoredVersion{Version: out, CertificatePEM: issued.CertificatePEM, EncryptedKey: cipher}); e != nil {
				return e
			}
			// This event is an invalidation, never an instruction to load queued bytes.
			_, e = s.events.EnqueueWithin(sc, "deployment.generation", "certificate/"+out.ID, json.RawMessage(`{"kind":"certificate"}`))
			return e
		})
	}
	if e != nil {
		failure, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		failed := s.tx.Within(failure, func(sc transaction.Scope) error {
			if e := s.graph.GuardWithin(sc); e != nil {
				return e
			}
			if e := s.repo.WriteLock(sc); e != nil {
				return e
			}
			return s.repo.Fail(sc, w, w.Attempt.Failed(s.now()))
		})
		return Version{}, errors.Join(domain.ErrUnavailable, failed)
	}
	return out, nil
}
func (s *Service) Import(ctx context.Context, a ActorRef, id string, cert, key []byte) (out Version, err error) {
	m := s.management
	if m == nil {
		return out, domain.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = m.security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.WriteLock(sc); e != nil {
			return e
		}
		if e := m.authorize(sc, a, "spec", id); e != nil {
			return e
		}
		r, e := s.repo.Read(sc, "spec", id, 0)
		if e != nil || !r.Enabled {
			return domain.ErrUnavailable
		}
		var spec Spec
		if json.Unmarshal(r.Body, &spec) != nil || spec.Method != "import" {
			return domain.ErrInvalid
		}
		// Imported replacement is a new spec revision requiring publication;
		// it cannot silently change an already published revision.
		if _, e = s.repo.Current(sc, id, r.Revision); e == nil {
			return domain.ErrConflict
		} else if !errors.Is(e, domain.ErrNotFound) {
			return e
		}
		var trustPEM []byte
		if spec.TrustID != "" {
			trust, e := s.repo.Read(sc, "trust", spec.TrustID, spec.TrustRevision)
			if e != nil || !trust.Enabled {
				return domain.ErrUnavailable
			}
			trustPEM = trust.PEM
		}
		out, e = s.crypto.Inspect(spec, cert, key, s.now(), trustPEM)
		if e != nil {
			return e
		}
		out.ID, e = s.crypto.NewID()
		if e != nil {
			return e
		}
		out.SpecID = id
		out.SpecRevision = r.Revision
		out.PrivateMaterialRef = out.ID
		cipher, e := m.leafSecrets.Seal("certificates/version/"+out.ID, key)
		if e != nil {
			return e
		}
		token, e := s.crypto.NewID()
		if e != nil {
			return e
		}
		attempt, e := s.repo.Claim(sc, id, r.Revision, token, s.now().Add(time.Minute))
		if e != nil {
			return e
		}
		if e = s.repo.Commit(sc, Work{Spec: r, Token: token, Attempt: attempt}, StoredVersion{Version: out, CertificatePEM: cert, EncryptedKey: cipher}); e != nil {
			return e
		}
		eventID, e := s.crypto.NewID()
		if e != nil {
			return e
		}
		body, _ := json.Marshal(map[string]string{"spec_id": id, "version_id": out.ID})
		return m.audit.Append(sc, audit.Event{ID: eventID, ActorID: a.UserID, Action: "certificates.version.imported", Payload: body})
	})
	if err != nil {
		return Version{}, err
	}
	return
}
func (s *Service) ReadMaterialsWithin(sc transaction.Scope, refs []MaterialRef) (Materials, error) {
	return s.readMaterials(sc, refs, true)
}
func (s *Service) ValidateMaterialsWithin(sc transaction.Scope, refs []MaterialRef) error {
	_, e := s.readMaterials(sc, refs, false)
	return e
}
func (s *Service) readMaterials(sc transaction.Scope, refs []MaterialRef, private bool) (out Materials, err error) {
	if e := s.repo.ReadLock(sc); e != nil {
		return out, e
	}
	refs = append([]MaterialRef{}, refs...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Kind+refs[i].ID < refs[j].Kind+refs[j].ID })
	generations := []string{}
	for _, ref := range refs {
		kind := ref.Kind
		if kind == "certificate" {
			kind = "spec"
		}
		if kind == "origin_pull_trust" {
			kind = "trust"
		}
		r, e := s.repo.Read(sc, kind, ref.ID, ref.Revision)
		if e != nil || !r.Enabled {
			return Materials{}, domain.ErrUnavailable
		}
		m := Material{Ref: ref}
		switch kind {
		case "spec":
			var spec Spec
			if json.Unmarshal(r.Body, &spec) != nil || (ref.Purpose != "" && spec.Purpose != ref.Purpose) {
				return Materials{}, domain.ErrUnavailable
			}
			if spec.TrustID != "" {
				trust, e := s.repo.Read(sc, "trust", spec.TrustID, spec.TrustRevision)
				if e != nil || !trust.Enabled {
					return Materials{}, domain.ErrUnavailable
				}
			}
			v, e := s.repo.Current(sc, ref.ID, ref.Revision)
			if e != nil || !v.Usable(s.now()) {
				return Materials{}, domain.ErrUnavailable
			}
			// Historical versions without immutable enrollment/verified key metadata
			// require renewal (or a fresh import revision), never guess provenance
			// from a mutable provider account or display issuer DN.
			managed := v.EnrollmentProvider == "internal-client" || v.EnrollmentProvider == "internal-server"
			if s.leafStatus == nil || (spec.Automatic() && v.EnrollmentProvider == "") || s.leafStatus.ValidateLeafWithin(sc, v.Version, managed) != nil {
				return Materials{}, domain.ErrUnavailable
			}
			// Expected DNS names are validated against the actual certificate by crypto.
			if e := s.crypto.Covers(v.CertificatePEM, ref.Names); e != nil {
				return Materials{}, domain.ErrUnavailable
			}
			var key []byte
			if private {
				if s.secrets == nil {
					return Materials{}, domain.ErrUnavailable
				}
				ciphertext := v.EncryptedKey
				if s.distribution != nil {
					binding := RecipientBinding{Node: s.node, Recipient: s.recipient, VersionID: v.ID}
					ciphertext, e = s.distribution.EnvelopeWithin(sc, binding)
					if e != nil {
						// Initial new material is sealed to the trusted role set. A node may
						// only derive its own envelope if it can actually decrypt that source.
						if e = s.distribution.RewrapWithin(sc, v.ID, []RecipientBinding{binding}); e != nil {
							return Materials{}, domain.ErrUnavailable
						}
						ciphertext, e = s.distribution.EnvelopeWithin(sc, binding)
					}
					if e != nil {
						return Materials{}, domain.ErrUnavailable
					}
				}
				key, e = s.secrets.Open("certificates/version/"+v.ID, ciphertext)
				if e != nil {
					return Materials{}, domain.ErrUnavailable
				}
			}
			m.Version = v.Version
			m.CertificatePEM = v.CertificatePEM
			m.KeyPEM = key
			generations = append(generations, v.ID)
		case "trust":
			var trust TrustBundle
			if json.Unmarshal(r.Body, &trust) != nil || (ref.Purpose != "" && trust.Purpose != ref.Purpose) {
				return Materials{}, domain.ErrUnavailable
			}
			if _, e := s.crypto.InspectTrust(trust.Purpose, r.PEM, s.now()); e != nil {
				return Materials{}, domain.ErrUnavailable
			}
			if s.status == nil || trust.StatusProfile == "" {
				return Materials{}, domain.ErrUnavailable
			}
			status, e := s.repo.Status(sc, ref.ID, ref.Revision, s.status.ProfileDigest(trust.StatusProfile))
			if e != nil || !s.now().Before(status.ValidUntil) || !status.UnknownResponderReady {
				return Materials{}, domain.ErrUnavailable
			}
			m.Status = &status
			m.TrustPEM = r.PEM
			m.OriginPullAuthorized = trust.OriginPullAuthorized
			if ref.Kind == "origin_pull_trust" && !m.OriginPullAuthorized {
				return Materials{}, domain.ErrUnavailable
			}
			generations = append(generations, s.crypto.Digest(r.PEM), status.Generation)
		default:
			return Materials{}, domain.ErrInvalid
		}
		out.Items = append(out.Items, m)
	}
	b, _ := json.Marshal(generations)
	out.Generation = s.crypto.Digest(b)
	return
}

func (s *Service) CleanupChallenges(ctx context.Context) error {
	if cleaner, ok := s.issuer.(interface{ Cleanup(context.Context) error }); ok {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return cleaner.Cleanup(ctx)
	}
	return nil
}

// SetEvents binds the owner invalidation port during process assembly only.
func (s *Service) SetEvents(events Events) { s.events = events }

func (s *Service) SetDistribution(d *Distribution, node NodeRef, recipient string) {
	s.distribution = d
	d.SetLeafStatus(s.leafStatus)
	s.node = node
	s.recipient = recipient
}
