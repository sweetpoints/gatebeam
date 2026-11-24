//go:build integration

// Package pkiauthority provisions identities on the fixture CA side.
package pkiauthority

import (
	"context"
	"time"

	"gatebeam/internal/modules/pki"
	"gatebeam/internal/modules/pki/application"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"

	"github.com/jackc/pgx/v5/pgxpool"
)

type security struct{ tx *postgres.Runner }

func (s security) Within(ctx context.Context, _ application.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}

type Operator struct {
	db       *pgxpool.Pool
	grants   *application.GrantService
	security security
	actor    application.ActorRef
}

func New(db *pgxpool.Pool, config pki.GrantConfig, recipient string) (*Operator, error) {
	s := security{postgres.NewRunner(db)}
	grants, err := pki.NewGrants(db, s, recipient, config)
	if err != nil {
		return nil, err
	}
	return &Operator{db: db, grants: grants, security: s, actor: application.ActorRef{UserID: "fixture-ca-operator"}}, nil
}

func (o *Operator) Enroll(ctx context.Context, directory string, purpose domain.Usage, name string) (application.Grant, application.EABCredentials, error) {
	grant, err := o.grants.Authorize(ctx, o.actor, application.GrantSpec{
		Names: []string{name}, Directory: directory, Purpose: purpose, Expires: time.Now().Add(time.Hour),
	})
	if err != nil {
		return application.Grant{}, application.EABCredentials{}, err
	}
	credentials, err := o.grants.IssueEAB(ctx, o.actor, grant.ID)
	return grant, credentials, err
}

func (o *Operator) Inspect(ctx context.Context, origin string) (application.QueryResult, error) {
	return pki.NewQueries(o.db, o.security, origin).Read(ctx, o.actor)
}

func (o *Operator) Disable(ctx context.Context, principal string) error {
	return o.grants.DisablePrincipal(ctx, o.actor, principal)
}

func (o *Operator) Revoke(ctx context.Context, issuer, serial string) error {
	return pki.NewRevocations(o.db, o.security).Revoke(ctx, o.actor, issuer, serial, 0)
}
