//go:build integration

package testkit_test

import (
	"context"
	"gatebeam/internal/platform/testkit"
	"testing"
)

func TestIndependentFixturesDoNotTruncateEachOther(t *testing.T) {
	one := testkit.Postgres(t)
	if _, e := one.Exec(context.Background(), `INSERT INTO audit(id,action,actor_id,payload) VALUES('fixture-one','test','actor','{}')`); e != nil {
		t.Fatal(e)
	}
	two := testkit.Postgres(t)
	var n int
	if e := one.QueryRow(context.Background(), "SELECT count(*) FROM audit").Scan(&n); e != nil || n != 1 {
		t.Fatal("second fixture erased first", n, e)
	}
	if e := two.QueryRow(context.Background(), "SELECT count(*) FROM audit").Scan(&n); e != nil || n != 0 {
		t.Fatal("fixture data leaked", n, e)
	}
}
