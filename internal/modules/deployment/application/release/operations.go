package release

import (
	"gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type ExecutionReport struct {
	Stage             string                     `json:"stage"`
	Cause             string                     `json:"cause"`
	UpdatedAt         time.Time                  `json:"updated_at"`
	JobState          string                     `json:"job_state"`
	Attempt           int                        `json:"attempt"`
	ConfigApplied     bool                       `json:"config_applied"`
	RouteVerification *runtime.RouteVerification `json:"route_verification,omitempty"`
}
type OperationsRepository interface {
	ExecutionWithin(transaction.Scope, string) (ExecutionReport, error)
	ProgressWithin(transaction.Scope, string, string, string) error
}

func (s *Service) ExecutionWithin(sc transaction.Scope, id string) (ExecutionReport, error) {
	r, ok := s.repo.(OperationsRepository)
	if !ok {
		return ExecutionReport{Stage: "unavailable", Cause: "unavailable"}, nil
	}
	return r.ExecutionWithin(sc, id)
}
func (s *Service) ProgressWithin(sc transaction.Scope, id, stage, cause string) error {
	if !ValidProgress(stage, cause) {
		return domain.ErrInvalid
	}
	r, ok := s.repo.(OperationsRepository)
	if !ok {
		return domain.ErrUnavailable
	}
	return r.ProgressWithin(sc, id, stage, cause)
}
func ValidProgress(stage, cause string) bool {
	switch stage {
	case "preparing", "validated", "applying", "verifying", "succeeded", "failed", "restoring", "restored", "restore_failed":
	default:
		return false
	}
	switch cause {
	case "none", "authority_or_preparation_failed", "compile_failed", "stage_failed", "native_validation_failed", "activation_or_observation_failed", "route_verification_failed", "confirmation_failed", "restore_failed", "unavailable":
		return true
	}
	return false
}
