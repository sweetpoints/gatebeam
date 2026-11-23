package postgres

import (
	"context"
	app "gatebeam/internal/modules/certificates/application"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type HTTPChallenges struct{}

func NewHTTPChallenges() *HTTPChallenges { return &HTTPChallenges{} }
func (*HTTPChallenges) PrepareWithin(sc transaction.Scope, c app.HTTPChallenge, targets []app.NodeRef) error {
	return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		// An active token may belong to only one issuance owner. Retired/expired
		// entries stay immutable until bounded cleanup, preventing ambiguous files.
		var mayClean bool
		if e := tx.QueryRow(ctx, `SELECT has_table_privilege(session_user,'certificates_http_challenges'::regclass,'DELETE')`).Scan(&mayClean); e != nil {
			return e
		}
		if mayClean {
			if _, e := tx.Exec(ctx, `DELETE FROM certificates_http_challenges WHERE expires_at<clock_timestamp()`); e != nil {
				return e
			}
		}

		_, e := tx.Exec(ctx, `INSERT INTO certificates_http_challenges(owner,token,key_authorization) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.Owner, c.Token, c.KeyAuthorization)
		if e != nil {
			return e
		}
		var match bool
		if e = tx.QueryRow(ctx, `SELECT owner=$1 AND key_authorization=$3 AND NOT retired AND expires_at>clock_timestamp() FROM certificates_http_challenges WHERE token=$2 FOR UPDATE`, c.Owner, c.Token, c.KeyAuthorization).Scan(&match); e != nil || !match {
			return app.ErrChallenge
		}
		for _, n := range targets {
			if _, e = tx.Exec(ctx, `INSERT INTO certificates_http_targets(owner,token,node_id,node_epoch) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, c.Owner, c.Token, n.ID, int64(n.Epoch)); e != nil {
				return e
			}
		}
		return nil
	})
}
func (*HTTPChallenges) ReadyWithin(sc transaction.Scope, owner string, targets []app.NodeRef) (ready bool, err error) {
	err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var tokens []string
		rows, e := tx.Query(ctx, `SELECT token FROM certificates_http_challenges WHERE owner=$1 AND NOT retired AND expires_at>clock_timestamp()`, owner)
		if e != nil {
			return e
		}
		for rows.Next() {
			var token string
			if e = rows.Scan(&token); e != nil {
				rows.Close()
				return e
			}
			tokens = append(tokens, token)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(tokens) == 0 {
			return nil
		}
		for _, token := range tokens {
			var count int
			if e = tx.QueryRow(ctx, `SELECT count(*) FROM certificates_http_targets WHERE owner=$1 AND token=$2`, owner, token).Scan(&count); e != nil {
				return e
			}
			if count != len(targets) {
				return nil
			}
			for _, n := range targets {
				var ok bool
				e = tx.QueryRow(ctx, `SELECT ready FROM certificates_http_targets WHERE owner=$1 AND token=$2 AND node_id=$3 AND node_epoch=$4`, owner, token, n.ID, int64(n.Epoch)).Scan(&ok)
				if e == pgx.ErrNoRows {
					return nil
				}
				if e != nil {
					return e
				}
				if !ok {
					return nil
				}
			}
		}
		ready = true
		return nil
	})
	return
}
func (*HTTPChallenges) CleanupWithin(sc transaction.Scope, owner string) error {
	return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE certificates_http_challenges SET retired=true WHERE owner=$1`, owner)
		return e
	})
}
func (*HTTPChallenges) PendingWithin(sc transaction.Scope, n app.NodeRef) (out []app.HTTPChallenge, err error) {
	err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT c.owner::text,c.token,c.key_authorization FROM certificates_http_challenges c JOIN certificates_http_targets t USING(owner,token) WHERE t.node_id=$1 AND t.node_epoch=$2 AND NOT c.retired AND c.expires_at>clock_timestamp() ORDER BY c.token LIMIT 129`, n.ID, int64(n.Epoch))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c app.HTTPChallenge
			if e = rows.Scan(&c.Owner, &c.Token, &c.KeyAuthorization); e != nil {
				return e
			}
			out = append(out, c)
		}
		if len(out) > 128 {
			return app.ErrChallenge
		}
		return rows.Err()
	})
	return
}
func (*HTTPChallenges) ResetWithin(sc transaction.Scope, n app.NodeRef) error {
	return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE certificates_http_targets SET ready=false WHERE node_id=$1 AND node_epoch=$2`, n.ID, int64(n.Epoch))
		return e
	})
}
func (*HTTPChallenges) AcknowledgeWithin(sc transaction.Scope, n app.NodeRef, pending []app.HTTPChallenge) error {
	return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		for _, c := range pending {
			tag, e := tx.Exec(ctx, `UPDATE certificates_http_targets t SET ready=true FROM certificates_http_challenges c WHERE c.owner=t.owner AND c.token=t.token AND t.owner=$1 AND t.token=$2 AND t.node_id=$3 AND t.node_epoch=$4 AND c.key_authorization=$5 AND NOT c.retired AND c.expires_at>clock_timestamp()`, c.Owner, c.Token, n.ID, int64(n.Epoch), c.KeyAuthorization)
			if e != nil {
				return e
			}
			if tag.RowsAffected() != 1 {
				return app.ErrChallenge
			}
		}
		return nil
	})
}
