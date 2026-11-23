package domain

import (
	"regexp"
	"time"
)

type SafeReport struct {
	ID                string    `json:"id"`
	ArtifactID        string    `json:"artifact_id,omitempty"`
	At                time.Time `json:"at"`
	Stage             string    `json:"stage"`
	Outcome           string    `json:"outcome"`
	Cause             string    `json:"cause"`
	BusinessActivated bool      `json:"business_activated"`
}

var reportID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func (r SafeReport) Valid() bool {
	if !reportID.MatchString(r.ID) || r.At.IsZero() || r.BusinessActivated || (r.ArtifactID != "" && !ValidDigest(r.ArtifactID)) {
		return false
	}
	if r.Outcome == "failed" {
		switch r.Stage {
		case "configuration":
			return r.Cause == "configuration_unavailable" && r.ArtifactID == ""
		case "verify":
			return r.Cause == "artifact_verification_failed" && r.ArtifactID == ""
		case "stage":
			return r.Cause == "isolated_stage_failed" && ValidDigest(r.ArtifactID)
		}
	}
	return r.Stage == "stage" && r.Outcome == "isolated_staged" && r.Cause == "manual_activation_required" && ValidDigest(r.ArtifactID)
}
