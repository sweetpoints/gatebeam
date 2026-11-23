//go:build integration

package publication_test

import (
	"context"
	"errors"
	"gatebeam/internal/integration/migration"
	"gatebeam/internal/modules/deployment/application/preflight"
	"testing"
)

type preflightCallback struct{ call func() }

func (p preflightCallback) Check(context.Context, string, preflight.EntryAddress) (preflight.Report, error) {
	p.call()
	return preflight.Report{Revision: 1, Ready: true, Result: "passed"}, nil
}
func TestPreflightRechecksCurrentScopedCredentialBeforeAndAfterProbe(t *testing.T) {
	f := setup(t)
	site := f.site(t, "scoped-preflight")
	ctx := context.Background()
	a := migration.ActorRef{UserID: f.publisher.UserID, AuthVersion: f.publisher.AuthVersion, CredentialKind: f.publisher.CredentialKind, CredentialID: f.publisher.CredentialID}
	calls := 0
	service := migration.New(f.access, preflightCallback{func() { calls++ }})
	if _, e := service.Check(ctx, a, site.ID, preflight.EntryAddress{}); !errors.Is(e, migration.ErrDenied) || calls != 0 {
		t.Fatal("unscoped user reached probe", e, calls)
	}
	f.grant(t, f.publisher, site.ID)
	service = migration.New(f.access, preflightCallback{func() {
		calls++
		f.exec(t, "UPDATE identity_sessions SET expires=clock_timestamp()-interval '1 second' WHERE id=$1", a.CredentialID)
	}})
	if _, e := service.Check(ctx, a, site.ID, preflight.EntryAddress{}); !errors.Is(e, migration.ErrDenied) || calls != 1 {
		t.Fatal("revoked credential received result", e, calls)
	}
}
