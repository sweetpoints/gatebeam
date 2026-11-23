// Package postgres owns deployment persistence. SQL accesses no other module tables.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	platformpg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type Store struct{}

func New() *Store             { return &Store{} }
func id(v string) pgtype.UUID { var u pgtype.UUID; _ = u.Scan(v); return u }
func use(sc transaction.Scope, fn func(context.Context, *dbgen.Queries) error) error {
	return platformpg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		e := fn(ctx, dbgen.New(tx))
		if errors.Is(e, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		return e
	})
}
func (*Store) Digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func (*Store) Save(sc transaction.Scope, c release.Candidate) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		return q.SaveCandidate(ctx, dbgen.SaveCandidateParams{ID: id(c.ID), Body: b, InputDigest: c.InputDigest})
	})
}
func (*Store) Read(sc transaction.Scope, v string) (out release.Candidate, err error) {
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		row, e := q.Candidate(ctx, id(v))
		if e != nil {
			return e
		}
		if e = json.Unmarshal(row.Body, &out); e != nil {
			return e
		}
		out.State = domain.State(row.State)
		out.ObservedVersion = row.ObservedVersion
		out.RestoredVersion = row.RestoredVersion
		out.Effective = row.Effective
		return nil
	})
	return
}
func (*Store) Queue(sc transaction.Scope, v string) (result string, created bool, err error) {
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		if _, e := q.LockCandidate(ctx, id(v)); e != nil {
			return e
		}
		n, e := q.QueueRelease(ctx, id(v))
		if e != nil {
			return e
		}
		created = n == 1
		result = v
		return nil
	})
	return
}
func (*Store) List(sc transaction.Scope, limit, offset int) (out []release.Candidate, err error) {
	out = []release.Candidate{}
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		rows, e := q.ListCandidates(ctx, dbgen.ListCandidatesParams{Limit: int32(limit), Offset: int32(offset)})
		if e != nil {
			return e
		}
		for _, r := range rows {
			var c release.Candidate
			if e = json.Unmarshal(r.Body, &c); e != nil {
				return e
			}
			c.State = domain.State(r.State)
			c.ObservedVersion = r.ObservedVersion
			c.RestoredVersion = r.RestoredVersion
			c.Effective = r.Effective
			out = append(out, c)
		}
		return nil
	})
	return
}
