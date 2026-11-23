package certificatematerials_test

import (
	"context"
	"errors"
	"gatebeam/internal/integration/certificatematerials"
	cert "gatebeam/internal/modules/certificates/application"
	deploy "gatebeam/internal/modules/deployment/application"
	"testing"
)

type absentPublication struct{}

func (absentPublication) Snapshot(context.Context) (deploy.Snapshot, error) {
	return deploy.Snapshot{}, errors.New("no verified publication")
}

type lifecycle struct{ cleaned, prepared bool }

func (l *lifecycle) CleanupChallenges(context.Context) error          { l.cleaned = true; return nil }
func (l *lifecycle) PrepareCurrent(context.Context) error             { l.prepared = true; return nil }
func (*lifecycle) PrepareStatus(context.Context, string, int64) error { return nil }
func (*lifecycle) EnsureRevision(context.Context, string, int64) (cert.Version, error) {
	return cert.Version{}, nil
}
func TestUnpublishedPreparationStillCleansDurableChallenges(t *testing.T) {
	owner := &lifecycle{}
	worker := certificatematerials.Worker{Published: absentPublication{}, Certificates: owner}
	_ = worker.Step(context.Background())
	if !owner.cleaned || !owner.prepared {
		t.Fatal("initial material lifecycle skipped cleanup or preparation", owner)
	}
}
