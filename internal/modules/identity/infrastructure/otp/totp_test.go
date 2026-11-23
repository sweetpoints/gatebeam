package otp

import (
	"testing"
	"time"
)

func TestRFC6238PublicVectorAndWindow(t *testing.T) {
	// RFC 6238 Appendix B SHA-1 public test key, reduced to six digits for interoperable authenticator apps.
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	o := New()
	step, e := o.Verify(seed, "287082", time.Unix(59, 0))
	if e != nil || step != 1 {
		t.Fatal(step, e)
	}
	if _, e = o.Verify(seed, "287082", time.Unix(120, 0)); e == nil {
		t.Fatal("outside window accepted")
	}
	if _, e = o.Verify(seed, "0287082", time.Unix(59, 0)); e == nil {
		t.Fatal("wrong digits accepted")
	}
}
