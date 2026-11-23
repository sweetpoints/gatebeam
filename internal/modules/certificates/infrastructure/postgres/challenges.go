package postgres

import (
	"context"
	"encoding/json"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/domain"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Challenge receipts are operational ownership, not configuration authority.
// They use short transactions and never acquire publication/deployment locks.
type Challenges struct{ tx transaction.Runner }

func NewChallenges(p *pgxpool.Pool) *Challenges { return &Challenges{pg.NewRunner(p)} }
func (c *Challenges) Save(ctx context.Context, r app.ChallengeReceipt) error {
	return c.tx.Within(ctx, func(sc transaction.Scope) error {
		return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			body, e := json.Marshal(r)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO certificates_challenges(owner,binding,body) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, r.Owner, r.Binding, body)
			if e != nil {
				return e
			}
			var oldJSON []byte
			if e = tx.QueryRow(ctx, `SELECT body FROM certificates_challenges WHERE owner=$1 AND binding=$2 FOR UPDATE`, r.Owner, r.Binding).Scan(&oldJSON); e != nil {
				return e
			}
			var old app.ChallengeReceipt
			if json.Unmarshal(oldJSON, &old) != nil {
				return domain.ErrInvalid
			}
			previousID := old.RecordID
			old.RecordID = r.RecordID
			if old != r || (previousID != "" && previousID != r.RecordID) {
				return domain.ErrConflict
			}
			_, e = tx.Exec(ctx, `UPDATE certificates_challenges SET body=$3 WHERE owner=$1 AND binding=$2`, r.Owner, r.Binding, body)
			return e
		})
	})
}
func (c *Challenges) Complete(ctx context.Context, owner, binding string) error {
	return c.tx.Within(ctx, func(sc transaction.Scope) error {
		return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `DELETE FROM certificates_challenges WHERE owner=$1 AND binding=$2`, owner, binding)
			return e
		})
	})
}
func (c *Challenges) Pending(ctx context.Context) (out []app.PendingChallenge, err error) {
	err = c.tx.Within(ctx, func(sc transaction.Scope) error {
		receipts := []app.ChallengeReceipt{}
		if e := pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			rows, e := tx.Query(ctx, `SELECT body FROM certificates_challenges WHERE created_at<clock_timestamp()-interval '2 minutes' ORDER BY created_at LIMIT 20`)
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var body []byte
				var r app.ChallengeReceipt
				if e = rows.Scan(&body); e != nil {
					return e
				}
				if e = json.Unmarshal(body, &r); e != nil {
					return e
				}
				receipts = append(receipts, r)
			}
			return rows.Err()
		}); e != nil {
			return e
		}
		for _, r := range receipts {
			credential, e := New().Read(sc, "credential", r.CredentialID, r.CredentialRevision)
			if e != nil {
				return e
			}
			out = append(out, app.PendingChallenge{Receipt: r, Credential: credential})
		}
		return nil
	})
	return
}
