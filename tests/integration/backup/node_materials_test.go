//go:build integration

package backup_test

import (
	"context"
	"encoding/json"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestNodeMaterialsSnapshotRestoresCiphertextWithoutChallengeReplay(t *testing.T) {
	snapshot, key, p := fixture(t)
	ctx := t.Context()
	id := uuid.NewString()
	node := uuid.NewString()
	for _, q := range []string{
		`INSERT INTO certificates_resources(kind,id,revision,enabled) VALUES('credential',$1,1,true)`,
		`INSERT INTO certificates_revisions(kind,id,revision,body,secret) VALUES('credential',$1,1,'{}','original-ciphertext')`,
		`INSERT INTO certificates_provider_envelopes(kind,id,revision,ciphertext) VALUES('credential',$1,1,'rewrapped-ciphertext')`,
		`INSERT INTO certificates_resources(kind,id,revision,enabled) VALUES('spec',$1,1,true)`,
		`INSERT INTO certificates_revisions(kind,id,revision,body) VALUES('spec',$1,1,'{}')`,
		`INSERT INTO certificates_versions(id,spec_id,spec_revision,body,certificate_pem,encrypted_key) VALUES($1,$1,1,'{}','public-certificate','original-leaf-ciphertext')`,
		`INSERT INTO certificates_http_challenges(owner,token,key_authorization) VALUES($1,'owned_token','owned_token.thumbprint')`,
	} {
		if _, e := p.Exec(ctx, q, id); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := p.Exec(ctx, `INSERT INTO certificates_node_envelopes(version_id,node_id,node_epoch,recipient,ciphertext) VALUES($1,$2,1,'age1-fixture-public','leaf-envelope')`, id, node); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO certificates_http_targets(owner,token,node_id,node_epoch,ready) VALUES($1,'owned_token',$2,1,true)`, id, node); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO observability_queries(id,state,actor,filter,objects,watermark,scan_bytes,expires_at) VALUES($1,'coordinating','{}','{}','[]',0,0,clock_timestamp()+interval '10 minutes')`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO observability_query_parts(query_id,node_id,node_epoch) VALUES($1,$2,1)`, id, node); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO observability_segments(id,physical_id,fingerprint,source_name,node_id) VALUES(repeat('a',64),repeat('a',64),'owned','access.log',$1)`, node); e != nil {
		t.Fatal(e)
	}
	artifact := create(t, snapshot)
	decoded, _, e := (recovery.Decoder{}).Decode(ctx, artifact.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"certificates_node_envelopes", "certificates_provider_envelopes", "certificates_http_challenges", "certificates_http_targets", "observability_query_parts"} {
		var rows []json.RawMessage
		if e = json.Unmarshal(decoded.Files["database/"+table+".json"], &rows); e != nil || len(rows) != 1 {
			t.Fatalf("schema26 %s missing: %d %v", table, len(rows), e)
		}
	}
	destination := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	restorer := application.Restorer{Decoder: recovery.Decoder{}, Destination: destination}
	report, e := restorer.Verify(ctx, artifact.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = restorer.Restore(ctx, report, application.Conservative); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP DATABASE `+destination.Database+` WITH (FORCE)`) })
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = destination.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	for _, table := range []string{"certificates_node_envelopes", "certificates_http_challenges", "certificates_http_targets", "observability_query_parts"} {
		var count int
		if e = restored.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&count); e != nil || count != 0 {
			t.Fatalf("old %s authority replayed: %d %v", table, count, e)
		}
	}
	var restoredNode string
	if e = restored.QueryRow(ctx, `SELECT node_id FROM observability_segments WHERE id=repeat('a',64)`).Scan(&restoredNode); e != nil || restoredNode != node {
		t.Fatal("source provenance lost", restoredNode, e)
	}
	var cipher []byte
	if e = restored.QueryRow(ctx, `SELECT ciphertext FROM certificates_provider_envelopes WHERE id=$1`, id).Scan(&cipher); e != nil || string(cipher) != "rewrapped-ciphertext" {
		t.Fatalf("encrypted provider representation lost: %v", e)
	}
}
