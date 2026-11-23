package release

import (
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
)

func (s *Service) RecordVerifiedWithin(sc transaction.Scope, id, artifact, version string) error {
	repo, ok := s.repo.(ExecutionRepository)
	if !ok {
		return domain.ErrUnavailable
	}
	if e := repo.RecordOutcome(sc, id, domain.Succeeded, version, ""); e != nil {
		return e
	}
	if r, ok := s.repo.(OperationsRepository); ok {
		if e := r.ProgressWithin(sc, id, "succeeded", "none"); e != nil {
			return e
		}
	}
	return repo.RecordVerified(sc, id, artifact, version)
}
func (s *Service) RecordOutcomeWithin(sc transaction.Scope, id string, state domain.State, version, restored string) error {
	switch state {
	case domain.Failed, domain.Restored, domain.RestoreFailed:
	default:
		return domain.ErrInvalid
	}
	repo, ok := s.repo.(ExecutionRepository)
	if !ok {
		return domain.ErrUnavailable
	}
	return repo.RecordOutcome(sc, id, state, version, restored)
}
func (s *Service) CurrentVerifiedWithin(sc transaction.Scope) (Candidate, VerifiedReceipt, error) {
	repo, ok := s.repo.(ExecutionRepository)
	if !ok {
		return Candidate{}, VerifiedReceipt{}, domain.ErrUnavailable
	}
	receipt, e := repo.CurrentVerified(sc)
	if e != nil {
		return Candidate{}, receipt, e
	}
	c, e := s.ReadWithin(sc, receipt.ReleaseID)
	if e == nil && c.State != domain.Succeeded {
		return Candidate{}, receipt, domain.ErrInvalid
	}
	return c, receipt, e
}
