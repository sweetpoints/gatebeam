package domain

import "testing"

func TestQueuedIsNotEffective(t *testing.T) {
	r := Release{ID: "release", State: Queued}
	if r.Effective() {
		t.Fatal("queued became effective")
	}
	if r.Transition(Succeeded) == nil {
		t.Fatal("unverified success accepted")
	}
	for _, state := range []State{Preparing, Validated, Applying, Verifying, Succeeded} {
		if e := r.Transition(state); e != nil {
			t.Fatal(e)
		}
	}
	if !r.Effective() {
		t.Fatal("verified state ineffective")
	}
}
func TestValidationFailureCannotClaimRestored(t *testing.T) {
	r := Release{State: Validated}
	if r.Transition(Restored) == nil {
		t.Fatal("never applied claimed restored")
	}
}
