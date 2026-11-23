package application

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

func (s *Service) SetStatus(status Attestor) { s.status = status }

// RefreshStatus performs bounded protocol I/O outside final activation locks;
// committing rechecks the current resource enablement and profile identity.
func (s *Service) RefreshStatus(ctx context.Context, id string, revision int64) error {
	if s.status == nil {
		return domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var record Record
	var trust TrustBundle
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.ReadLock(sc); e != nil {
			return e
		}
		var e error
		record, e = s.repo.Read(sc, "trust", id, revision)
		if e != nil || !record.Enabled {
			return domain.ErrUnavailable
		}
		return json.Unmarshal(record.Body, &trust)
	})
	if e != nil {
		return e
	}
	attestation, e := s.status.Attest(ctx, trust, record.PEM, s.now())
	if e != nil {
		return e
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := s.repo.WriteLock(sc); e != nil {
			return e
		}
		fresh, e := s.repo.Read(sc, "trust", id, revision)
		if e != nil || !fresh.Enabled || attestation.ProfileDigest != s.status.ProfileDigest(trust.StatusProfile) || !s.now().Before(attestation.ValidUntil) {
			return domain.ErrConflict
		}
		if e = s.repo.SaveStatus(sc, id, revision, attestation); e != nil {
			return e
		}
		_, e = s.events.EnqueueWithin(sc, "deployment.generation", "revocation/"+attestation.Generation, json.RawMessage(`{"kind":"revocation"}`))
		return e
	})
}
