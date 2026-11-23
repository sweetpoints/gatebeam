package postgres

import (
	"context"
	"encoding/json"
	"errors"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type roleCipher interface {
	Open(string, []byte) ([]byte, error)
	Seal(string, []byte) ([]byte, error)
}

func (r *Store) RewrapRoleWithin(sc transaction.Scope, secret roleCipher) (int, error) {
	return r.roleSecretsWithin(sc, secret, true)
}
func (r *Store) VerifyRoleWithin(sc transaction.Scope, secret roleCipher) (int, error) {
	return r.roleSecretsWithin(sc, secret, false)
}
func (*Store) roleSecretsWithin(sc transaction.Scope, secret roleCipher, write bool) (count int, err error) {
	if write {
		if err = New().WriteLock(sc); err != nil {
			return
		}
	}
	err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if !write {
			if _, e := tx.Exec(ctx, `SET TRANSACTION READ ONLY`); e != nil {
				return e
			}
		}
		type record struct {
			kind, id string
			revision int64
			cipher   []byte
		}
		var records []record
		rows, e := tx.Query(ctx, `SELECT v.kind,v.id::text,v.revision,coalesce(e.ciphertext,v.secret) FROM certificates_revisions v LEFT JOIN certificates_provider_envelopes e USING(kind,id,revision) WHERE v.kind IN('account','credential') AND octet_length(v.secret)>0 ORDER BY v.kind,v.id,v.revision LIMIT 4097`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var r record
			if e = rows.Scan(&r.kind, &r.id, &r.revision, &r.cipher); e != nil {
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
			body, _ := json.Marshal([]any{r.kind, r.id, r.revision})
			label := "certificates/" + string(body)
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
			if _, e = tx.Exec(ctx, `INSERT INTO certificates_provider_envelopes(kind,id,revision,ciphertext) VALUES($1,$2,$3,$4) ON CONFLICT(kind,id,revision) DO UPDATE SET ciphertext=excluded.ciphertext`, r.kind, r.id, r.revision, cipher); e != nil {
				return e
			}
			count++
		}
		return nil
	})
	return
}
