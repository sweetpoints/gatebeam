package operations

import (
	"context"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"os"
	"path/filepath"
	"testing"
)

type captureRunner struct{ Calls int }

func (c *captureRunner) Run(context.Context, string, ...string) ([]byte, error) {
	c.Calls++
	return []byte(`{}`), nil
}
func TestHostDispatchUnknownCannotBeReissued(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(dir, 0700)
	r := &captureRunner{}
	j := HostJournal{Directory: dir, Runner: r}
	s := upgrade.Step{ID: "33333333-3333-4333-8333-333333333333-001", Kind: "update"}
	if e := j.Dispatch(t.Context(), s); e != nil {
		t.Fatal(e)
	}
	if e := j.Dispatch(t.Context(), s); e == nil || r.Calls != 1 {
		t.Fatal("unknown host dispatch repeated")
	}
	count := 0
	if e := j.Execute(t.Context(), s.ID, func(context.Context, upgrade.Step) error { count++; return context.DeadlineExceeded }); e == nil {
		t.Fatal("failure lost")
	}
	if e := j.Execute(t.Context(), s.ID, func(context.Context, upgrade.Step) error { count++; return nil }); e == nil || count != 1 {
		t.Fatal("failed host command rerun")
	}
}
