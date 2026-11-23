//go:build integration

package postgres_test

import (
	repo "gatebeam/internal/modules/backup/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"strings"
	"testing"
)

func TestBackupRecordsNeverTreatDeliveryAsArtifactVerification(t *testing.T) {
	p := testkit.Postgres(t)
	for i, body := range []string{`{"Files":[{"Name":"database/identity_accounts.json"}]}`, `{"detail_status":"omitted_for_recovery","artifact_verification":"required"}`} {
		if _, e := p.Exec(t.Context(), `INSERT INTO backup_runs(id,created_at,manifest,cipher_sha256,bytes)VALUES($1,clock_timestamp(),$2,$3,128)`, strings.Repeat([]string{"a", "b"}[i], 64), body, strings.Repeat("c", 64)); e != nil {
			t.Fatal(e)
		}
	}
	if e := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		rows, e := (repo.Catalog{DB: p}).RecordsWithin(sc, 25, 0)
		if e != nil {
			return e
		}
		if len(rows) != 2 {
			t.Fatal("catalog rows missing")
		}
		seen := map[string]bool{}
		for _, r := range rows {
			seen[r.DetailStatus] = true
			if r.ArtifactVerification != "required" {
				t.Fatal("delivery receipt claimed offline verification")
			}
		}
		if !seen["omitted_for_recovery"] || !seen["recorded"] {
			t.Fatal("historical metadata omission hidden")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
