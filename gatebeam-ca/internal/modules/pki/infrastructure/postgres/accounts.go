package postgres

import (
	"context"
	"errors"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/modules/pki/infrastructure/postgres/dbgen"
	platform "gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
)

func use(sc transaction.Scope, fn func(context.Context, *dbgen.Queries) error) error {
	e := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error { return fn(ctx, dbgen.New(tx)) })
	if errors.Is(e, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) && pg.Code == "23505" {
		return app.ErrConflict
	}
	return e
}
func account(v dbgen.PkiAccount) domain.Account {
	return domain.Account{ID: v.ID, PrincipalID: v.PrincipalID, Directory: v.Directory, Thumbprint: v.Thumbprint, Key: v.PublicKey, Status: v.Status, Contacts: v.Contacts, Revision: v.Revision}
}
func (*Store) Account(sc transaction.Scope, d, id string) (domain.Account, error) {
	var a domain.Account
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.AccountByID(c, dbgen.AccountByIDParams{Directory: d, ID: id})
		a = account(v)
		return e
	})
	return a, e
}
func (*Store) AccountByKey(sc transaction.Scope, d, key string) (domain.Account, error) {
	var a domain.Account
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.AccountByKey(c, dbgen.AccountByKeyParams{Directory: d, Thumbprint: key})
		a = account(v)
		return e
	})
	return a, e
}

// All CA and management mutations serialize on this principal lock before
// acquiring binding/account rows. Advisory locks avoid granting CA any ability
// to update principal policy merely to obtain SELECT FOR UPDATE locks.
func (*Store) Principal(sc transaction.Scope, id string) (domain.Principal, error) {
	var p domain.Principal
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		if e := q.LockPrincipalID(c, "gatebeam-ca/pki/principal/"+id); e != nil {
			return e
		}
		v, e := q.LockPrincipal(c, id)
		p = domain.Principal{ID: v.ID, Names: v.Names, Usage: domain.Usage(v.Purpose), Directory: v.Directory, Expires: v.Expires.Time, Disabled: v.Disabled}
		return e
	})
	return p, e
}
func (*Store) BindingPrincipal(sc transaction.Scope, id string) (string, error) {
	var out string
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		out, e = q.BindingPrincipal(c, id)
		return e
	})
	return out, e
}
func (*Store) Binding(sc transaction.Scope, id string) (domain.Binding, error) {
	var b domain.Binding
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.ReadBinding(c, id)
		b = domain.Binding{ID: v.ID, PrincipalID: v.PrincipalID, Cipher: v.Cipher, Expires: v.Expires.Time, Consumed: v.Consumed}
		return e
	})
	if e == nil {
		e = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			var cipher []byte
			err := tx.QueryRow(ctx, `SELECT ciphertext FROM pki_eab_envelopes WHERE id=$1`, id).Scan(&cipher)
			if err == pgx.ErrNoRows {
				return nil
			}
			if err == nil {
				b.Cipher = cipher
			}
			return err
		})
	}
	return b, e
}
func (*Store) ConsumeBinding(sc transaction.Scope, id string) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.ConsumeBinding(c, id)
		if e == nil && n != 1 {
			return app.ErrDenied
		}
		return e
	})
}
func (*Store) InsertAccount(sc transaction.Scope, a domain.Account) error {
	if a.Contacts == nil {
		a.Contacts = []string{}
	}
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.InsertAccount(c, dbgen.InsertAccountParams{ID: a.ID, PrincipalID: a.PrincipalID, Directory: a.Directory, Thumbprint: a.Thumbprint, PublicKey: a.Key, Status: a.Status, Contacts: a.Contacts})
	})
}
func (*Store) SaveAccount(sc transaction.Scope, a domain.Account) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		return q.SaveAccount(c, dbgen.SaveAccountParams{ID: a.ID, Thumbprint: a.Thumbprint, PublicKey: a.Key, Status: a.Status, Contacts: a.Contacts})
	})
}
func (*Store) AddNonce(sc transaction.Scope, digest string, expires time.Time) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		if e := q.CleanupNonces(c); e != nil {
			return e
		}
		return q.AddNonce(c, dbgen.AddNonceParams{Digest: digest, Expires: pgtype.Timestamptz{Time: expires, Valid: true}})
	})
}
func (*Store) ConsumeNonce(sc transaction.Scope, digest string, now time.Time) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.ConsumeNonce(c, dbgen.ConsumeNonceParams{Digest: digest, Expires: pgtype.Timestamptz{Time: now, Valid: true}})
		if e == nil && n != 1 {
			return app.ErrBadNonce
		}
		return e
	})
}
