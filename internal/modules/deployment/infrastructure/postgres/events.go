package postgres

import (
	"encoding/json"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/transaction"
)

// Events translates owner invalidations into the active deployment model. It
// never accepts a draft, actor, or caller-provided node identity.
type Events struct{ queue *jobs.Store }

func NewEvents(queue *jobs.Store) *Events { return &Events{queue} }
func (e *Events) EnqueueWithin(sc transaction.Scope, kind, key string, payload json.RawMessage) (string, error) {
	if kind != "deployment.generation" {
		return "", domain.ErrInvalid
	}
	var invalidation struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(payload, &invalidation) != nil || !domain.DerivedKind(invalidation.Kind) {
		return "", domain.ErrInvalid
	}
	targets, err := New().ActiveNodeTargets(sc)
	if err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return e.queue.EnqueueWithin(sc, kind, key, payload)
	}
	var first string
	for _, target := range targets {
		id, err := e.queue.EnqueueTargetWithin(sc, "deployment.node.generation.v1", key, payload, jobs.ClaimTarget{NodeID: target.ID, Epoch: target.Epoch})
		if err != nil {
			return "", err
		}
		if first == "" {
			first = id
		}
	}
	return first, nil
}
