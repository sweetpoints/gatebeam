package reports

import (
	"context"
	"gatebeam/internal/modules/backup/application"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSafeReportPersistsOnlyFixedMetadataAndRejectsUnknownFields(t *testing.T) {
	s := Store{Directory: t.TempDir()}
	r := application.SafeReport{ID: "11111111-1111-4111-8111-111111111111", At: time.Now().UTC(), Stage: "verify", Outcome: "failed", Cause: "artifact_verification_failed"}
	if e := s.Write(r); e != nil {
		t.Fatal(e)
	}
	got, e := s.Latest(context.Background())
	if e != nil || got == nil || *got != r {
		t.Fatal("persisted report changed", e)
	}
	if e = os.WriteFile(filepath.Join(s.Directory, name), []byte(`{"id":"11111111-1111-4111-8111-111111111111","private_key":"must-not-be-read"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if got, e = s.Latest(context.Background()); e == nil || got != nil {
		t.Fatal("untrusted report fields accepted")
	}
}
