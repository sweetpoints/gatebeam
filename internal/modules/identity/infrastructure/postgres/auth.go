// Package postgres implements identity persistence; generated database types stay here.
package postgres

import (
	"context"
	"errors"
	"gatebeam/internal/modules/identity/application/auth"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/modules/identity/infrastructure/postgres/dbgen"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
)

type Repository struct{}

func New() *Repository { return &Repository{} }
func use(sc transaction.Scope, fn func(context.Context, *dbgen.Queries) error) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		e := fn(ctx, dbgen.New(tx))
		if errors.Is(e, pgx.ErrNoRows) {
			return auth.ErrNotFound
		}
		return e
	})
}
func ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func account(a dbgen.IdentityAccount) domain.Account {
	return domain.Account{ID: a.ID, Name: a.Name, Role: domain.Role(a.Role), PasswordHash: a.PasswordHash, State: domain.State(a.State), AuthVersion: a.AuthVersion, LastStep: a.LastStep, Seed: a.Seed, InviteHash: a.InviteHash, InviteExpires: a.InviteExpires.Time, Failures: a.Failures, LockedUntil: a.LockedUntil.Time}
}
func (r *Repository) Lock(sc transaction.Scope) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { return q.LockIdentity(c) })
}
func (r *Repository) Empty(sc transaction.Scope) (bool, error) {
	var v bool
	e := use(sc, func(c context.Context, q *dbgen.Queries) error { var e error; v, e = q.EmptyAccounts(c); return e })
	return v, e
}
func (r *Repository) AccountByName(sc transaction.Scope, name string) (domain.Account, error) {
	var a domain.Account
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.AccountByName(c, name)
		a = account(v)
		return e
	})
	return a, e
}
func (r *Repository) AccountByID(sc transaction.Scope, id string) (domain.Account, error) {
	var a domain.Account
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.AccountByID(c, id)
		a = account(v)
		return e
	})
	return a, e
}
func (r *Repository) AccountByInvite(sc transaction.Scope, hash string) (domain.Account, error) {
	var a domain.Account
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.AccountByInvite(c, hash)
		a = account(v)
		return e
	})
	return a, e
}
func (r *Repository) CreateAccount(sc transaction.Scope, a domain.Account) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.CreateAccount(c, dbgen.CreateAccountParams{Role: string(a.Role), ID: a.ID, Name: a.Name, PasswordHash: a.PasswordHash, State: string(a.State), AuthVersion: a.AuthVersion, LastStep: a.LastStep, Seed: a.Seed, InviteHash: a.InviteHash, InviteExpires: ts(a.InviteExpires), Failures: a.Failures, LockedUntil: ts(a.LockedUntil)})
	})
}
func (r *Repository) SaveAccount(sc transaction.Scope, a domain.Account) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.SaveAccount(c, dbgen.SaveAccountParams{ID: a.ID, PasswordHash: a.PasswordHash, State: string(a.State), AuthVersion: a.AuthVersion, LastStep: a.LastStep, Seed: a.Seed, InviteHash: a.InviteHash, InviteExpires: ts(a.InviteExpires), Failures: a.Failures, LockedUntil: ts(a.LockedUntil)})
	})
}
func (r *Repository) SaveChallenge(sc transaction.Scope, a domain.Challenge) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.SaveChallenge(c, dbgen.SaveChallengeParams{Hash: a.Hash, AccountID: a.AccountID, AuthVersion: a.AuthVersion, Expires: ts(a.Expires), Attempts: a.Attempts, Consumed: a.Consumed})
	})
}
func (r *Repository) Challenge(sc transaction.Scope, hash string) (domain.Challenge, error) {
	var a domain.Challenge
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.Challenge(c, hash)
		a = domain.Challenge{Hash: v.Hash, AccountID: v.AccountID, AuthVersion: v.AuthVersion, Expires: v.Expires.Time, Attempts: v.Attempts, Consumed: v.Consumed}
		return e
	})
	return a, e
}
func (r *Repository) CreateSession(sc transaction.Scope, a domain.Session) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.CreateSession(c, dbgen.CreateSessionParams{ID: a.ID, AccountID: a.AccountID, TokenHash: a.TokenHash, CsrfHash: a.CSRFHash, AuthVersion: a.AuthVersion, Expires: ts(a.Expires), Revoked: a.Revoked})
	})
}
func (r *Repository) Session(sc transaction.Scope, hash string) (domain.Session, error) {
	var a domain.Session
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.Session(c, hash)
		a = domain.Session{ID: v.ID, AccountID: v.AccountID, TokenHash: v.TokenHash, CSRFHash: v.CsrfHash, AuthVersion: v.AuthVersion, Expires: v.Expires.Time, Revoked: v.Revoked}
		return e
	})
	return a, e
}
func (r *Repository) RevokeSession(sc transaction.Scope, id string) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { return q.RevokeSession(c, id) })
}
func (r *Repository) ReplaceRecovery(sc transaction.Scope, id string, hashes []string) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		if e := q.ClearRecovery(c, id); e != nil {
			return e
		}
		for _, hash := range hashes {
			if e := q.AddRecovery(c, dbgen.AddRecoveryParams{AccountID: id, Hash: hash}); e != nil {
				return e
			}
		}
		return nil
	})
}
func (r *Repository) ConsumeRecovery(sc transaction.Scope, id, hash string) (bool, error) {
	var n int64
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		n, e = q.ConsumeRecovery(c, dbgen.ConsumeRecoveryParams{AccountID: id, Hash: hash})
		return e
	})
	return n == 1, e
}
