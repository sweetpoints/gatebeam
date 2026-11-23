//go:build integration

package backup_test

import (
	"context"
	"fmt"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestRestoreCannotReviveNodeOrCAAuthority(t *testing.T) {
	for _, version := range []int64{22, 23, 24, 25, 26, 27} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s, key, p := fixtureAt(t, version)
			ctx := t.Context()
			if _, e := p.Exec(ctx, `INSERT INTO identity_accounts(id,name,password_hash,state,auth_version,seed,invite_expires,locked_until,role) VALUES('historical','historical','old','active',1,'cipher','infinity','-infinity','admin')`); e != nil {
				t.Fatal(e)
			}
			if _, e := p.Exec(ctx, `INSERT INTO observability_segments(id,physical_id,fingerprint,source_name) VALUES(repeat('a',64),repeat('a',64),'owned','access.log')`); e != nil {
				t.Fatal(e)
			}
			if version >= 24 {
				if _, e := p.Exec(ctx, `INSERT INTO deployment_nodes(id,epoch,principal,registration,enabled) VALUES('11111111-1111-4111-8111-111111111111',1,'historical-edge','{}',true)`); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := p.Exec(ctx, `INSERT INTO pki_issuers(id,fingerprint,certificate_der,not_before,not_after) VALUES('historical-issuer','owned-fingerprint','public-der',clock_timestamp()-interval '1 day',clock_timestamp()+interval '1 year')`); e != nil {
				t.Fatal(e)
			}
			if version >= 27 {
				if _, e := p.Exec(ctx, `INSERT INTO deployment_upgrade_runs(id,revision,owner_instance,state,document) VALUES('33333333-3333-4333-8333-333333333333',1,'old-executor','paused','{"state":"paused"}')`); e != nil {
					t.Fatal(e)
				}
			}
			artifact := create(t, s)
			decoded, _, e := (recovery.Decoder{}).Decode(ctx, artifact.Path, key)
			if e != nil {
				t.Fatal(e)
			}
			contract, e := recovery.SchemaContract(version)
			if e != nil || decoded.Manifest.Schema != contract.Digest {
				t.Fatal("wrong source contract", version, e)
			}
			d := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
			r := application.Restorer{Decoder: recovery.Decoder{}, Destination: d}
			report, e := r.Verify(ctx, artifact.Path, key)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Restore(ctx, report, application.Conservative); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP DATABASE `+d.Database+` WITH (FORCE)`) })
			cfg := p.Config().Copy()
			cfg.ConnConfig.Database = d.Database
			delete(cfg.ConnConfig.RuntimeParams, "search_path")
			out, e := pgxpool.NewWithConfig(ctx, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer out.Close()
			var valid bool
			for _, sql := range []string{
				`SELECT state='disabled' AND password_hash='' FROM identity_accounts WHERE id='historical'`,
				`SELECT NOT EXISTS(SELECT 1 FROM deployment_nodes WHERE enabled OR state<>'quarantined')`,
				`SELECT NOT EXISTS(SELECT 1 FROM jobs) AND NOT EXISTS(SELECT 1 FROM observability_query_parts)`,
				`SELECT EXISTS(SELECT 1 FROM pki_restore_quarantine WHERE issuer_id='historical-issuer')`,
				`SELECT node_id='legacy' FROM observability_segments WHERE id=repeat('a',64)`,
				`SELECT NOT EXISTS(SELECT 1 FROM deployment_upgrade_runs WHERE state<>'quarantined' OR document->>'state'<>'quarantined')`,
			} {
				if e = out.QueryRow(ctx, sql).Scan(&valid); e != nil || !valid {
					t.Fatal("historical restore escaped quarantine", version, sql, e)
				}
			}
		})
	}
}
