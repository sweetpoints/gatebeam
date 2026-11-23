package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/platform/jobs/dbgen"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"regexp"
	"time"
)

type ClaimTarget struct {
	NodeID string
	Epoch  uint64
}

func (t ClaimTarget) Valid() bool {
	id, err := uuid.Parse(t.NodeID)
	return err == nil && id != uuid.Nil && id.String() == t.NodeID && t.Epoch > 0 && t.Epoch <= 1<<63-1
}
func targetUUID(target ClaimTarget) pgtype.UUID {
	id, _ := uuid.Parse(target.NodeID)
	return pgtype.UUID{Bytes: id, Valid: true}
}

var directedKind = regexp.MustCompile(`^[a-z][a-z0-9_-]*\.node\.[a-z][a-z0-9_-]*\.v1$`)

func targetKinds(kinds []string) bool {
	if len(kinds) == 0 || len(kinds) > 16 {
		return false
	}
	for _, kind := range kinds {
		if !directedKind.MatchString(kind) || len(kind) > 128 {
			return false
		}
	}
	return true
}
func cleanupKind(kind string) bool {
	return kind == "deployment.node.rotate_logs.v1" || kind == "observability.node.ingest.v1"
}

// StopClaims is separate from process cancellation. Existing leased work may
// finish within its deadline, and local log cleanup keeps running during drain.
func (s *Store) StopClaims() { s.claimMu.Lock(); defer s.claimMu.Unlock(); s.draining.Store(true) }

func (s *Store) EnqueueTargetWithin(sc transaction.Scope, kind, key string, payload json.RawMessage, target ClaimTarget) (id string, err error) {
	if !target.Valid() || !targetKinds([]string{kind}) || len(key) == 0 || len(key) > 1024 || len(payload) > 65536 || !json.Valid(payload) {
		return "", errors.New("invalid directed job")
	}
	// Retain the existing global unique constraint for bridge binaries. Directed
	// keys include the complete incarnation; fanout cannot collapse into one job.
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s", target.NodeID, target.Epoch, key)))
	scopedKey := "node/" + hex.EncodeToString(sum[:])
	err = postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		id, e = dbgen.New(tx).EnqueueTarget(ctx, dbgen.EnqueueTargetParams{Kind: kind, Key: scopedKey, Payload: payload, TargetNodeID: targetUUID(target), TargetNodeEpoch: pgtype.Int8{Int64: int64(target.Epoch), Valid: true}})
		return e
	})
	return
}

func (s *Store) ClaimTargetKinds(ctx context.Context, worker string, target ClaimTarget, lease time.Duration, kinds []string) (job Job, err error) {
	s.claimMu.RLock()
	defer s.claimMu.RUnlock()
	if worker == "" || len(worker) > 256 || !target.Valid() || lease <= 0 || lease > time.Hour || !targetKinds(kinds) {
		return job, errors.New("invalid node claim")
	}
	if !acceptCleanup(ctx) {
		return job, ErrDraining
	}
	if s.draining.Load() || !acceptGlobal(ctx) {
		var local []string
		for _, kind := range kinds {
			if cleanupKind(kind) {
				local = append(local, kind)
			}
		}
		if len(local) == 0 {
			return job, ErrDraining
		}
		kinds = local
	}
	err = s.runner.Within(ctx, func(sc transaction.Scope) error {
		return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			q := dbgen.New(tx)
			if e := q.ExhaustTargetKinds(ctx, dbgen.ExhaustTargetKindsParams{NodeID: targetUUID(target), NodeEpoch: int64(target.Epoch), Kinds: kinds}); e != nil {
				return e
			}
			row, e := q.ClaimTargetKinds(ctx, dbgen.ClaimTargetKindsParams{NodeID: targetUUID(target), NodeEpoch: int64(target.Epoch), Kinds: kinds, Worker: worker, LeaseSeconds: lease.Seconds()})
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			if e != nil {
				return e
			}
			if e = q.RecordAttempt(ctx, dbgen.RecordAttemptParams{JobID: row.ID, Attempt: row.Attempt, LeaseToken: row.LeaseToken.String, Worker: worker}); e != nil {
				return e
			}
			job = Job{ID: row.ID, Kind: row.Kind, Payload: row.Payload, LeaseToken: row.LeaseToken.String, Deadline: row.Deadline.Time, Attempt: int(row.Attempt), Target: ClaimTarget{NodeID: uuid.UUID(row.TargetNodeID.Bytes).String(), Epoch: uint64(row.TargetNodeEpoch.Int64)}}
			return nil
		})
	})
	if err == nil && job.ID == "" {
		err = ErrNoJob
	}
	return
}
func (s *Store) Renew(ctx context.Context, id, token string, lease time.Duration) error {
	if id == "" || token == "" || lease <= 0 || lease > time.Hour {
		return ErrLeaseLost
	}
	return s.runner.Within(ctx, func(sc transaction.Scope) error {
		return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			n, err := dbgen.New(tx).Renew(ctx, dbgen.RenewParams{ID: id, LeaseToken: pgtype.Text{String: token, Valid: true}, LeaseSeconds: lease.Seconds()})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrLeaseLost
			}
			return nil
		})
	})
}
func (s *Store) Release(ctx context.Context, id, token string) error {
	return s.runner.Within(ctx, func(sc transaction.Scope) error {
		return postgres.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			q := dbgen.New(tx)
			n, err := q.Release(ctx, dbgen.ReleaseParams{ID: id, LeaseToken: pgtype.Text{String: token, Valid: true}})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrLeaseLost
			}
			return q.CompleteAttempt(ctx, dbgen.CompleteAttemptParams{JobID: id, LeaseToken: token})
		})
	})
}
