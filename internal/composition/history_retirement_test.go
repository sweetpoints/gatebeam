package composition

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/transaction"
	"testing"
)

type retirementScope struct{ ctx context.Context }

func (s retirementScope) Context() context.Context { return s.ctx }

type retirementRunner struct{}

func (retirementRunner) Within(ctx context.Context, fn func(transaction.Scope) error) error {
	return fn(retirementScope{ctx})
}

type retirementFixture struct {
	stage    string
	failure  error
	finished int
}

func (f *retirementFixture) Discover(context.Context) ([]domain.Segment, error) {
	if f.stage == "discover" {
		return nil, f.failure
	}
	return []domain.Segment{{Closed: true}}, nil
}
func (f *retirementFixture) Close() error {
	if f.stage == "close" {
		return f.failure
	}
	return nil
}
func (f *retirementFixture) RemoveRetired(domain.Segment) error {
	if f.stage == "remove" || f.stage == "sync" {
		return f.failure
	}
	return nil
}
func (f *retirementFixture) BeginRetirement(transaction.Scope, domain.Segment) error {
	if f.stage == "begin" {
		return f.failure
	}
	if f.stage == "incomplete" {
		return domain.ErrIncomplete
	}
	return nil
}
func (f *retirementFixture) Retirements(transaction.Scope) ([]repo.Retirement, error) {
	if f.stage == "list" {
		return nil, f.failure
	}
	if f.stage == "incomplete" {
		return nil, nil
	}
	return []repo.Retirement{{ID: "approved"}}, nil
}
func (f *retirementFixture) FinishRetirement(transaction.Scope, string) error {
	f.finished++
	if f.stage == "finish" {
		return f.failure
	}
	return nil
}
func TestRetirementStagesPropagateUnexpectedFailures(t *testing.T) {
	for _, stage := range []string{"open", "discover", "begin", "list", "remove", "sync", "finish", "close", "incomplete"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("SECRET source path and backend error")
			f := &retirementFixture{stage: stage, failure: failure}
			e := retireSources(t.Context(), retirementRunner{}, f, func() (retirementSource, error) {
				if stage == "open" {
					return nil, failure
				}
				return f, nil
			})
			if stage == "incomplete" {
				if e != nil || f.finished != 0 {
					t.Fatal("not-ready intent was a failure", e, f.finished)
				}
				return
			}
			if !errors.Is(e, failure) {
				t.Fatal("retirement failure was swallowed", stage, e)
			}
			if stage != "finish" && stage != "close" && f.finished != 0 {
				t.Fatal("failure finalized intent", stage)
			}
		})
	}
}
