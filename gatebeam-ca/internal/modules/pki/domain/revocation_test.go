package domain

import (
	"errors"
	"testing"
	"time"
)

func TestRevocationIsTerminalAndReasonsAreStandard(t *testing.T) {
	now := time.Now().UTC()
	for _, reason := range []int{0, 1, 3, 4, 5, 9} {
		v, e := NewRevocation(Serial("0000000000000000000000000000000000000001"), reason, now)
		if e != nil || v.Reason != reason || !v.At.Equal(now) {
			t.Fatal("valid reason rejected", reason, e)
		}
		if e = v.Revoke(reason, now.Add(time.Hour)); !errors.Is(e, ErrAlreadyRevoked) {
			t.Fatal("revocation changed", e)
		}
	}
	for _, reason := range []int{-1, 2, 6, 7, 8, 10, 11} {
		if _, e := NewRevocation("0000000000000000000000000000000000000001", reason, now); !errors.Is(e, ErrRevocationReason) {
			t.Fatal("unsupported leaf reason accepted", reason, e)
		}
	}
}
