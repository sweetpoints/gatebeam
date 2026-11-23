package postgres

import (
	"context"
	"encoding/json"
	query "gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) PrepareLocalWithin(sc transaction.Scope, job query.Job, targets []query.LocalNode) (out query.Job, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		in, _, e := scanInput(tx.QueryRow(ctx, `SELECT `+queryCols+` FROM observability_queries WHERE id=$1 AND state='queued' FOR UPDATE`, job.ID))
		if e != nil {
			return e
		}
		if in.Filter.Source != "local" || len(targets) == 0 || len(targets) > 2 {
			return domain.ErrInvalid
		}
		seen := map[string]bool{}
		for _, n := range targets {
			if !domain.ValidSite(n.NodeID) || n.Epoch == 0 || n.Epoch > 1<<63-1 || seen[n.NodeID] {
				return domain.ErrInvalid
			}
			seen[n.NodeID] = true
		}
		coverage := "local_pending"
		for _, o := range in.Objects {
			if !seen[o.NodeID] {
				coverage = "local_unassigned"
			}
		}
		for _, n := range targets {
			objects := []domain.Object{}
			for _, o := range in.Objects {
				if o.NodeID == n.NodeID {
					objects = append(objects, o)
				}
			}
			raw, _ := json.Marshal(objects)
			if _, e = tx.Exec(ctx, `INSERT INTO observability_query_parts(query_id,node_id,node_epoch,objects) VALUES($1,$2,$3,$4)`, job.ID, n.NodeID, int64(n.Epoch), raw); e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE observability_queries SET state='coordinating',coverage=$2 WHERE id=$1`, job.ID, coverage); e != nil {
			return e
		}
		out = in.Job
		out.State = "coordinating"
		out.Coverage = coverage
		return nil
	})
	return
}
func (s *Store) claimLocalWithin(sc transaction.Scope) (in query.Input, found bool, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		token := uuid.NewString()
		var id string
		var objects []byte
		e := tx.QueryRow(ctx, `UPDATE observability_query_parts p SET state='running',lease=$3,lease_until=clock_timestamp()+interval '75 seconds' WHERE (query_id,node_id,node_epoch)=(SELECT p.query_id,p.node_id,p.node_epoch FROM observability_query_parts p JOIN observability_queries q ON q.id=p.query_id WHERE p.node_id=$1 AND p.node_epoch=$2 AND q.state='coordinating' AND q.created_at>clock_timestamp()-interval '90 seconds' AND q.expires_at>clock_timestamp()+interval '75 seconds' AND (p.state='queued' OR p.state='running' AND p.lease_until<clock_timestamp()) ORDER BY q.created_at LIMIT 1 FOR UPDATE OF p SKIP LOCKED) RETURNING query_id::text,objects`, s.nodeID, int64(s.nodeEpoch), token).Scan(&id, &objects)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		in, _, e = scanInput(tx.QueryRow(ctx, `SELECT `+queryCols+` FROM observability_queries WHERE id=$1`, id))
		if e != nil {
			return e
		}
		if e = json.Unmarshal(objects, &in.Objects); e != nil {
			return e
		}
		in.Token = token
		in.Target = query.LocalNode{NodeID: s.nodeID, Epoch: s.nodeEpoch}
		found = true
		return nil
	})
	return
}
func (s *Store) LeaseCurrentWithin(sc transaction.Scope, in query.Input) (current bool, err error) {
	if in.Target.NodeID != s.nodeID || in.Target.Epoch != s.nodeEpoch {
		return false, domain.ErrDenied
	}
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observability_query_parts p JOIN observability_queries q ON q.id=p.query_id WHERE p.query_id=$1 AND p.node_id=$2 AND p.node_epoch=$3 AND p.lease=$4 AND p.state='running' AND p.lease_until>clock_timestamp() AND q.state='coordinating' AND q.created_at>clock_timestamp()-interval '90 seconds' AND q.expires_at>clock_timestamp())`, in.Job.ID, s.nodeID, int64(s.nodeEpoch), in.Token).Scan(&current)
	})
	return
}
func (s *Store) completeLocalWithin(sc transaction.Scope, in query.Input, rows []domain.QueryRow, code string) error {
	if in.Target.NodeID != s.nodeID || in.Target.Epoch != s.nodeEpoch || len(rows) > domain.MaxQueryRows {
		return domain.ErrDenied
	}
	for _, row := range rows {
		if row.NodeID != s.nodeID {
			return domain.ErrSourceChanged
		}
	}
	raw, e := json.Marshal(rows)
	if e != nil || len(raw) > 8<<20 {
		return domain.ErrCapacity
	}
	state := "succeeded"
	if code != "" {
		switch code {
		case "query_failed", "denied", "capacity", "timeout":
			state = "failed"
			raw = []byte(`[]`)
		case "busy":
			state = "queued"
			code = ""
			raw = []byte(`[]`)
		default:
			return domain.ErrInvalid
		}
	}
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		if e := tx.QueryRow(ctx, `SELECT id::text FROM observability_queries WHERE id=$1 AND state='coordinating' AND created_at>clock_timestamp()-interval '90 seconds' AND expires_at>clock_timestamp() FOR UPDATE`, in.Job.ID).Scan(&id); e != nil {
			return domain.ErrIncomplete
		}
		result, e := tx.Exec(ctx, `UPDATE observability_query_parts SET state=$5,result=$6,error=$7,lease=NULL,lease_until=NULL WHERE query_id=$1 AND node_id=$2 AND node_epoch=$3 AND lease=$4 AND lease_until>clock_timestamp() AND state='running'`, in.Job.ID, s.nodeID, int64(s.nodeEpoch), in.Token, state, raw, code)
		if e != nil {
			return e
		}
		if result.RowsAffected() != 1 {
			return domain.ErrIncomplete
		}
		return aggregateLocal(ctx, tx, in.Job.ID, false)
	})
}
func aggregateLocal(ctx context.Context, tx pgx.Tx, id string, expired bool) error {
	var coverage string
	if e := tx.QueryRow(ctx, `SELECT coverage FROM observability_queries WHERE id=$1 FOR UPDATE`, id).Scan(&coverage); e != nil {
		return e
	}
	result, e := tx.Query(ctx, `SELECT node_id::text,state,result,error,truncated FROM observability_query_parts WHERE query_id=$1 ORDER BY node_id,node_epoch`, id)
	if e != nil {
		return e
	}
	parts := []query.NodePart{}
	pending := false
	for result.Next() {
		var p query.NodePart
		var raw []byte
		if e = result.Scan(&p.NodeID, &p.State, &raw, &p.Error, &p.Truncated); e != nil {
			result.Close()
			return e
		}
		if len(raw) > 0 {
			if e = json.Unmarshal(raw, &p.Rows); e != nil {
				result.Close()
				return e
			}
		}
		if p.State == "queued" || p.State == "running" {
			if expired {
				p.State = "unavailable"
				p.Error = "node_unavailable"
			} else {
				pending = true
			}
		}
		parts = append(parts, p)
	}
	e = result.Err()
	result.Close()
	if e != nil {
		return e
	}
	rows, merged, truncated := query.Merge(parts, domain.MaxQueryRows)
	state := "succeeded"
	if pending {
		state = "coordinating"
	}
	if coverage == "local_unassigned" {
		merged = "incomplete"
	}
	if pending {
		if coverage != "local_unassigned" {
			coverage = "local_pending"
		}
	} else {
		coverage = "local_" + merged
	}
	body, e := json.Marshal(rows)
	if e != nil || len(body) > 8<<20 {
		return domain.ErrCapacity
	}
	_, e = tx.Exec(ctx, `UPDATE observability_queries SET state=$2,result=$3,coverage=$4,truncated=$5 WHERE id=$1`, id, state, body, coverage, truncated)
	return e
}
func (s *Store) ExpireLocalWithin(sc transaction.Scope) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id::text FROM observability_queries WHERE state='coordinating' AND created_at<=clock_timestamp()-interval '90 seconds' ORDER BY created_at LIMIT 64 FOR UPDATE SKIP LOCKED`)
		if e != nil {
			return e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, id := range ids {
			if e = aggregateLocal(ctx, tx, id, true); e != nil {
				return e
			}
		}
		return nil
	})
}
