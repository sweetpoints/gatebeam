package password

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestArgon2idSaltVerifyAndBoundedParsing(t *testing.T) {
	var raw [24]byte
	if _, e := rand.Read(raw[:]); e != nil {
		t.Fatal(e)
	}
	password := base64.RawStdEncoding.EncodeToString(raw[:])
	h := New()
	a, e := h.Hash(password)
	if e != nil {
		t.Fatal(e)
	}
	b, e := h.Hash(password)
	if e != nil {
		t.Fatal(e)
	}
	if a == b {
		t.Fatal("salt reused")
	}
	ok, upgrade := h.Verify(a, password)
	if !ok || upgrade {
		t.Fatal("current hash rejected")
	}
	if ok, _ = h.Verify(a, password+"x"); ok {
		t.Fatal("wrong password accepted")
	}
	for _, v := range []string{"garbage", "$argon2id$v=19$m=4294967295,t=999,p=255$invalid$invalid"} {
		if ok, _ = h.Verify(v, password); ok {
			t.Fatal("malformed hash accepted")
		}
	}
}
