package domain

import "testing"

func TestJournalRejectsUnverifiedCommitAndUnsafeRestore(t *testing.T) {
	j := ApplyJournal{CandidateID: "candidate", State: Queued}
	if e := j.Advance(Succeeded); e == nil {
		t.Fatal("unverified success accepted")
	}
	for _, state := range []State{Preparing, Validated, Applying, Verifying, Succeeded} {
		if e := j.Advance(state); e != nil {
			t.Fatal(e)
		}
	}
	if j.State != Succeeded {
		t.Fatal(j.State)
	}
	if !DerivedKind("certificate") || !DerivedKind("revocation") || DerivedKind("draft") || DerivedKind("shell") {
		t.Fatal("derived capability whitelist")
	}
}
