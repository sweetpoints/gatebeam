package application

import (
	"testing"
	"time"
)

func TestSafeReportRejectsImpossibleOrSecretLikeMetadata(t *testing.T) {
	valid := SafeReport{ID: "11111111-1111-4111-8111-111111111111", At: time.Now(), Stage: "verify", Outcome: "failed", Cause: "artifact_verification_failed"}
	if !valid.Valid() {
		t.Fatal("actual verification failure rejected")
	}
	for _, change := range []func(*SafeReport){func(r *SafeReport) { r.Outcome = "isolated_staged" }, func(r *SafeReport) { r.Cause = "configuration_unavailable" }, func(r *SafeReport) { r.ArtifactID = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }, func(r *SafeReport) { r.BusinessActivated = true }, func(r *SafeReport) { r.ID = "secret-contents-must-never-be-exposed!" }} {
		v := valid
		change(&v)
		if v.Valid() {
			t.Fatalf("unsafe/impossible report accepted: stage=%s outcome=%s", v.Stage, v.Outcome)
		}
	}
}
