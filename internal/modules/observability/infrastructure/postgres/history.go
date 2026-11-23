package postgres

import (
	"context"
	"encoding/json"
	"errors"
	query "gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s *Store) PendingWithin(sc transaction.Scope) (b domain.Batch, found bool, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var raw []byte
		e := tx.QueryRow(ctx, `SELECT id,objects,node_id FROM observability_batches WHERE NOT local_cleaned AND node_id=$1 ORDER BY committed_at,id LIMIT 1`, s.nodeID).Scan(&b.ID, &raw, &b.NodeID)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return json.Unmarshal(raw, &b.Objects)
	})
	return
}
func (s *Store) CommitManifestWithin(sc transaction.Scope, m domain.Manifest) error {
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT objects FROM observability_batches WHERE id=$1 AND node_id=$2 FOR UPDATE`, m.BatchID, s.nodeID).Scan(&raw); e != nil {
			return e
		}
		var want []domain.Object
		if e := json.Unmarshal(raw, &want); e != nil {
			return e
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(m.Objects)
		if string(a) != string(b) {
			return domain.ErrSourceChanged
		}
		var seq int64
		e := tx.QueryRow(ctx, `INSERT INTO observability_manifests(batch_id,node_id) VALUES($1,$2) ON CONFLICT(batch_id) DO UPDATE SET batch_id=excluded.batch_id RETURNING sequence`, m.BatchID, s.nodeID).Scan(&seq)
		if e != nil {
			return e
		}
		for _, o := range m.Objects {
			if !domain.ValidObject(o) {
				return domain.ErrInvalid
			}
			r, _ := json.Marshal(o)
			_, e = tx.Exec(ctx, `INSERT INTO observability_archive_objects(object_key,manifest_sequence,site_id,min_time,max_time,bytes,metadata,node_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, o.Key, seq, o.SiteID, o.MinTime, o.MaxTime, o.Bytes, r, s.nodeID)
			if e != nil {
				return e
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO outbox(event_id,event_type,schema_version,aggregate_id,aggregate_version,payload) VALUES($1,'ArchiveCommitted',1,$2,1,'{}') ON CONFLICT DO NOTHING`, "archive/"+m.BatchID, m.BatchID)
		if e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
func (s *Store) CleanedWithin(sc transaction.Scope, id string) error {
	applied := false
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		result, e := tx.Exec(ctx, `UPDATE observability_batches SET local_cleaned=true WHERE id=$1 AND node_id=$2 AND NOT local_cleaned AND EXISTS(SELECT 1 FROM observability_manifests WHERE batch_id=$1 AND state='committed')`, id, s.nodeID)
		if e != nil {
			return e
		}
		applied = result.RowsAffected() == 1
		return nil
	})
	if err != nil || !applied {
		return err
	}
	return alertOutcome(sc, "ArchivePipelineChanged", "local-log-volume", "pipeline", "resolved", 0)
}

func (s *Store) SubmitWithin(sc transaction.Scope, a query.ActorRef, f query.Filter) (j query.Job, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		// Shared lifecycle lock freezes deletion while this snapshot is inserted.
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended('observability_manifest_lifecycle',0))`); e != nil {
			return e
		}
		// Serial admission prevents concurrent submitters bypassing the bounded queue.
		if _, e := tx.Exec(ctx, `LOCK TABLE observability_queries IN SHARE ROW EXCLUSIVE MODE`); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DELETE FROM observability_queries WHERE expires_at<clock_timestamp()`); e != nil {
			return e
		}
		var count int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM observability_queries`).Scan(&count); e != nil {
			return e
		}
		if count >= 64 {
			return domain.ErrCapacity
		}
		if e := tx.QueryRow(ctx, `SELECT coalesce(max(sequence),0) FROM observability_manifests WHERE state='committed'`).Scan(&j.Watermark); e != nil {
			return e
		}
		selection := `SELECT o.metadata FROM observability_archive_objects o JOIN observability_manifests m ON m.sequence=o.manifest_sequence WHERE m.state='committed' AND m.sequence<=$1 AND o.site_id=ANY($2) AND o.min_time<$4 AND o.max_time>=$3 ORDER BY o.object_key LIMIT 4097`
		if f.Source == "local" {
			selection = `SELECT obj FROM observability_batches b, jsonb_array_elements(b.objects) obj WHERE NOT b.local_cleaned AND obj->>'SiteID'=ANY($2) AND (obj->>'MinTime')::timestamptz<$4 AND (obj->>'MaxTime')::timestamptz>=$3 AND $1::bigint>=0 ORDER BY obj->>'Key' LIMIT 4097`
		}
		rows, e := tx.Query(ctx, selection, j.Watermark, f.SiteIDs, f.From, f.To)
		if e != nil {
			return e
		}
		objects := []domain.Object{}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return e
			}
			var o domain.Object
			if e = json.Unmarshal(raw, &o); e != nil {
				rows.Close()
				return e
			}
			objects = append(objects, o)
			j.ScanBytes += o.Bytes
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
		if e = domain.ValidateObjects(f, objects); e != nil {
			return e
		}
		j.Coverage = "archived_only"
		if f.Source == "local" {
			j.Coverage = "local_only"
		}
		j.ManifestObjects = len(objects)
		j.ID = uuid.NewString()
		j.State = "queued"
		j.ExpiresAt = time.Now().Add(10 * time.Minute)
		ar, _ := json.Marshal(a)
		fr, _ := json.Marshal(f)
		ob, _ := json.Marshal(objects)
		_, e = tx.Exec(ctx, `INSERT INTO observability_queries(id,state,actor,filter,objects,watermark,scan_bytes,expires_at) VALUES($1,'queued',$2,$3,$4,$5,$6,$7)`, j.ID, ar, fr, ob, j.Watermark, j.ScanBytes, j.ExpiresAt)
		return e
	})
	return
}
func scanInput(row pgx.Row) (in query.Input, result []domain.QueryRow, err error) {
	var a, f, o, r []byte
	err = row.Scan(&in.Job.ID, &in.Job.State, &a, &f, &o, &in.Job.Watermark, &in.Job.ScanBytes, &in.Job.ExpiresAt, &in.Job.Error, &r, &in.Token, &in.Job.Coverage, &in.Job.Truncated)
	if err != nil {
		return
	}
	for _, v := range []struct {
		b   []byte
		out any
	}{{a, &in.Actor}, {f, &in.Filter}, {o, &in.Objects}} {
		if err = json.Unmarshal(v.b, v.out); err != nil {
			return
		}
	}
	if in.Job.Coverage == "" {
		in.Job.Coverage = "archived_only"
		if in.Filter.Source == "local" {
			in.Job.Coverage = "local_only"
		}
	}
	in.Job.ManifestObjects = len(in.Objects)
	if len(r) > 0 {
		err = json.Unmarshal(r, &result)
	}
	return
}

const queryCols = `id::text,state,actor,filter,objects,watermark,scan_bytes,expires_at,error,result,coalesce(lease::text,''),coverage,truncated`

func (s *Store) FetchWithin(sc transaction.Scope, id string) (in query.Input, rows []domain.QueryRow, err error) {
	if _, e := uuid.Parse(id); e != nil {
		return in, nil, domain.ErrInvalid
	}
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		in, rows, e = scanInput(tx.QueryRow(ctx, `SELECT `+queryCols+` FROM observability_queries WHERE id=$1`, id))
		if errors.Is(e, pgx.ErrNoRows) {
			return domain.ErrDenied
		}
		return e
	})
	return
}
func (s *Store) ClaimWithin(sc transaction.Scope) (in query.Input, found bool, err error) {
	if s.nodeID != "legacy" && s.nodeEpoch > 0 {
		in, found, err = s.claimLocalWithin(sc)
		if err != nil || found {
			return
		}
	}
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM observability_queries WHERE expires_at<clock_timestamp()`); e != nil {
			return e
		}
		token := uuid.NewString()
		var e error
		in, _, e = scanInput(tx.QueryRow(ctx, `UPDATE observability_queries SET state='running',lease=$1,lease_until=clock_timestamp()+interval '75 seconds' WHERE id=(SELECT id FROM observability_queries WHERE (coalesce(filter->>'source','')<>'local' OR $2='legacy') AND expires_at>clock_timestamp()+interval '75 seconds' AND (state='queued' OR state='running' AND lease_until<clock_timestamp()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+queryCols, token, s.nodeID))
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		found = e == nil
		return e
	})
	return
}
func (s *Store) CompleteWithin(sc transaction.Scope, in query.Input, rows []domain.QueryRow, code string) error {
	if in.Target.NodeID != "" {
		return s.completeLocalWithin(sc, in, rows, code)
	}
	alertState := ""
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if len(rows) > domain.MaxQueryRows {
			return domain.ErrCapacity
		}
		raw, e := json.Marshal(rows)
		if e != nil || len(raw) > 8<<20 {
			return domain.ErrCapacity
		}
		state := "succeeded"
		if code != "" {
			if code != "query_failed" && code != "denied" && code != "capacity" && code != "timeout" && code != "busy" {
				return domain.ErrInvalid
			}
			state = "failed"
			raw = []byte(`[]`)
			if code == "busy" {
				state = "queued"
				code = ""
			}
		}

		result, e := tx.Exec(ctx, `UPDATE observability_queries SET state=$3,result=$4,error=$5,lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2 AND lease_until>clock_timestamp() AND expires_at>clock_timestamp()`, in.Job.ID, in.Token, state, raw, code)
		if e != nil {
			return e
		}
		if result.RowsAffected() != 1 {
			return domain.ErrIncomplete
		}
		if code == "denied" || state == "queued" {
			return nil
		}
		alertState = "resolved"
		if code != "" {
			alertState = "firing"
		}
		return nil
	})
	if err != nil || alertState == "" {
		return err
	}
	return alertOutcome(sc, "QueryPipelineChanged", "local-log-volume", "pipeline", alertState, 0)
}

func (s *Store) BeginDeleteWithin(sc transaction.Scope, id string) (objects []domain.Object, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('observability_manifest_lifecycle',0))`); e != nil {
			return e
		}
		var seq int64
		var state string
		if e := tx.QueryRow(ctx, `SELECT sequence,state FROM observability_manifests WHERE batch_id=$1 FOR UPDATE`, id).Scan(&seq, &state); e != nil {
			return e
		}
		if state == "deleted" {
			return nil
		}
		var cleaned bool
		if e := tx.QueryRow(ctx, `SELECT local_cleaned FROM observability_batches WHERE id=$1`, id).Scan(&cleaned); e != nil {
			return e
		}
		if !cleaned {
			return domain.ErrIncomplete
		}
		var busy bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observability_queries q, jsonb_array_elements(q.objects) obj JOIN observability_archive_objects o ON o.object_key=obj->>'Key' WHERE o.manifest_sequence=$1 AND q.state IN ('queued','running','coordinating') AND q.expires_at>clock_timestamp())`, seq).Scan(&busy); e != nil {
			return e
		}
		if busy {
			return domain.ErrIncomplete
		}
		rows, e := tx.Query(ctx, `SELECT metadata FROM observability_archive_objects WHERE manifest_sequence=$1 ORDER BY object_key`, seq)
		if e != nil {
			return e
		}
		for rows.Next() {
			var raw []byte
			var o domain.Object
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return e
			}
			if e = json.Unmarshal(raw, &o); e != nil {
				rows.Close()
				return e
			}
			objects = append(objects, o)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE observability_manifests SET state='deleting' WHERE sequence=$1`, seq)
		return e
	})
	return
}
func (s *Store) FinishDeleteWithin(sc transaction.Scope, id string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE observability_manifests SET state='deleted' WHERE batch_id=$1 AND state='deleting'`, id)
		return e
	})
}

func (s *Store) SpoolReferences(sc transaction.Scope) (refs map[string]bool, err error) {
	refs = map[string]bool{}
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT o->>'Key' FROM observability_batches b,jsonb_array_elements(b.objects) o WHERE NOT local_cleaned AND b.node_id=$1 LIMIT 16385`, s.nodeID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			if e = rows.Scan(&key); e != nil {
				return e
			}
			refs[key] = true
			if len(refs) > 16384 {
				return domain.ErrCapacity
			}
		}
		return rows.Err()
	})
	return
}
