package release

import (
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

var ErrNotFound = domain.ErrNotFound

// MaterialBinding is public immutable certificate identity, never PEM or a key.
type MaterialBinding struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Revision  int64  `json:"revision"`
	VersionID string `json:"version_id"`
	Digest    string `json:"digest"`
}
type VerifiedBindings struct {
	ArtifactID string            `json:"artifact_id"`
	Version    string            `json:"version"`
	Generation string            `json:"generation"`
	VerifiedAt time.Time         `json:"verified_at"`
	Materials  []MaterialBinding `json:"materials"`
}
type bindingRepository interface {
	SaveMaterialBindings(transaction.Scope, []MaterialBinding) error
	CurrentMaterialBindings(transaction.Scope) (VerifiedBindings, error)
}

func (s *Service) RecordVerifiedMaterialsWithin(sc transaction.Scope, id, artifact, version string, bindings []MaterialBinding) error {
	repo, ok := s.repo.(bindingRepository)
	if !ok {
		return domain.ErrUnavailable
	}
	if e := s.RecordVerifiedWithin(sc, id, artifact, version); e != nil {
		return e
	}
	return repo.SaveMaterialBindings(sc, bindings)
}
func (s *Service) CurrentMaterialBindingsWithin(sc transaction.Scope) (VerifiedBindings, error) {
	repo, ok := s.repo.(bindingRepository)
	if !ok {
		return VerifiedBindings{}, domain.ErrUnavailable
	}
	return repo.CurrentMaterialBindings(sc)
}
