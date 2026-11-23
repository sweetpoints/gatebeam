package domain

// ApplyJournal records local OS progress, not a database commit. ReceiptPending
// remains true until the separate authority transaction has acknowledged success.
type ApplyJournal struct {
	CandidateID     string `json:"candidate_id"`
	ArtifactID      string `json:"artifact_id"`
	PreviousVersion string `json:"previous_version"`
	Version         string `json:"version"`
	State           State  `json:"state"`
	ReceiptPending  bool   `json:"receipt_pending"`
}

func (j *ApplyJournal) Advance(next State) error {
	r := Release{ID: j.CandidateID, State: j.State}
	if e := r.Transition(next); e != nil {
		return e
	}
	j.State = r.State
	return nil
}

// DerivedKind is an internal capability, never a public caller-supplied actor.
func DerivedKind(kind string) bool {
	switch kind {
	case "certificate", "revocation", "health", "dns", "cloudflare", "management":
		return true
	}
	return false
}
