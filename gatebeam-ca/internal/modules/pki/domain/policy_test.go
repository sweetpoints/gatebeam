package domain

import "testing"

func TestPolicyRequiresExplicitInternalFQDNsAndExactAuthorization(t *testing.T) {
	for _, names := range [][]string{nil, {"localhost"}, {"*.internal.test"}, {"127.0.0.1"}, {"bad..internal.test"}, {"UPPER.internal.test"}, {"-bad.internal.test"}} {
		if _, e := NewPolicy(names, ServerAuth); e == nil {
			t.Fatalf("accepted %v", names)
		}
	}
	p, e := NewPolicy([]string{"server.internal.test"}, ServerAuth)
	if e != nil {
		t.Fatal(e)
	}
	for _, names := range [][]string{nil, {"other.internal.test"}, {"server.internal.test", "server.internal.test"}} {
		if e = p.Authorize(names); e == nil {
			t.Fatalf("authorized %v", names)
		}
	}
	if e = p.Authorize([]string{"server.internal.test"}); e != nil {
		t.Fatal(e)
	}
	if _, e = NewPolicy([]string{"server.internal.test"}, Usage("both")); e == nil {
		t.Fatal("mixed purpose accepted")
	}
}
