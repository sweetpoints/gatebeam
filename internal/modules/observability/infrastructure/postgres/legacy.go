package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

// MapLegacyArchivesWithin is a controlled historical metadata operation. It
// never authorizes opening or relabelling a raw volume. The registry's original
// flag was established from the original native runtime proof, not an IP guess.
func (s *Store) MapLegacyArchivesWithin(sc transaction.Scope, node string, proof map[string]string) error {
	if !domain.ValidSite(node) || len(proof) == 0 || len(proof) > domain.MaxQueryObjects {
		return domain.ErrInvalid
	}
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('observability_manifest_lifecycle',0))`); e != nil {
			return e
		}
		ids := []string{}
		keys := []string{}
		for key, checksum := range proof {
			var batch string
			var raw []byte
			e := tx.QueryRow(ctx, `SELECT m.batch_id,o.metadata FROM observability_archive_objects o JOIN observability_manifests m ON m.sequence=o.manifest_sequence WHERE o.object_key=$1 AND o.node_id='legacy' AND m.state='committed'`, key).Scan(&batch, &raw)
			var obj domain.Object
			if e != nil || json.Unmarshal(raw, &obj) != nil || checksum != obj.Checksum {
				return domain.ErrSourceChanged
			}
			ids = append(ids, batch)
			keys = append(keys, key)
		}
		var complete bool
		if e := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM observability_batches b,jsonb_array_elements(b.objects) o WHERE b.id=ANY($1) AND (NOT b.local_cleaned OR NOT (o->>'Key'=ANY($2))))`, ids, keys).Scan(&complete); e != nil {
			return e
		}
		if !complete {
			return domain.ErrIncomplete
		}
		_, e := tx.Exec(ctx, `UPDATE observability_archive_objects SET node_id=$1,metadata=jsonb_set(metadata,'{NodeID}',to_jsonb($1::text)) WHERE object_key=ANY($2) AND node_id='legacy'`, node, keys)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE observability_manifests SET node_id=$1 WHERE batch_id=ANY($2) AND node_id='legacy'`, node, ids)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE observability_batches b SET node_id=$1,objects=(SELECT coalesce(jsonb_agg(jsonb_set(o,'{NodeID}',to_jsonb($1::text))),'[]'::jsonb) FROM jsonb_array_elements(b.objects) o) WHERE id=ANY($2) AND node_id='legacy'`, node, ids)
		// Source cursors remain legacy: archived metadata ownership never
		// authorizes resuming a raw inode as the new node.
		return e
	})
}
