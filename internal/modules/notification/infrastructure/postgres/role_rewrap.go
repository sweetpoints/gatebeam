package postgres

import (
	"context"
	"errors"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type roleCipher interface {
	Open(string, []byte) ([]byte, error)
	Seal(string, []byte) ([]byte, error)
}

// RewrapRoleWithin changes only encryption representation under owner row locks.
// The original key holder must successfully open every row before commit.
func (r *Store) RewrapRoleWithin(sc transaction.Scope, secret roleCipher) (int, error) {
	return r.roleSecretsWithin(sc, secret, true)
}
func (r *Store) VerifyRoleWithin(sc transaction.Scope, secret roleCipher) (int, error) {
	return r.roleSecretsWithin(sc, secret, false)
}
func (*Store) roleSecretsWithin(sc transaction.Scope, secret roleCipher, write bool) (count int, err error) {
	err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if !write {
			if _, e := tx.Exec(ctx, `SET TRANSACTION READ ONLY`); e != nil {
				return e
			}
		}
		type record struct {
			id     string
			cipher []byte
		}
		var records []record
		querySQL := `SELECT id,secret FROM notification_channels WHERE octet_length(secret)>0 ORDER BY id LIMIT 4097`
		if write {
			querySQL += ` FOR UPDATE`
		}
		rows, e := tx.Query(ctx, querySQL)
		if e != nil {
			return e
		}
		for rows.Next() {
			var r record
			if e = rows.Scan(&r.id, &r.cipher); e != nil {
				rows.Close()
				return e
			}
			records = append(records, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(records) > 4096 {
			return errors.New("role rewrap row limit exceeded")
		}
		for _, r := range records {
			label := "notification/channel/" + r.id
			plain, e := secret.Open(label, r.cipher)
			if e != nil {
				return e
			}
			if !write {
				clear(plain)
				count++
				continue
			}
			cipher, e := secret.Seal(label, plain)
			clear(plain)
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `UPDATE notification_channels SET secret=$2 WHERE id=$1`, r.id, cipher); e != nil {
				return e
			}
			count++
		}
		return nil
	})
	return
}
