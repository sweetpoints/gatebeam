package duckdb

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestQueryChildOpenFileBudget(t *testing.T) {
	if value := os.Getenv("GATEBEAM_TEST_CHILD_NOFILE"); value != "" {
		limit, e := strconv.ParseUint(value, 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		if e = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: limit, Max: limit}); e != nil {
			t.Fatal(e)
		}
		e = CheckOpenFileBudget(t.Context())
		if (e == nil) != (limit >= RequiredOpenFiles) {
			t.Fatalf("limit=%d result=%v", limit, e)
		}
		return
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, limit := range []string{"1024", "12288"} {
		t.Run(limit, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestQueryChildOpenFileBudget$")
			cmd.Env = append(os.Environ(), "GATEBEAM_TEST_CHILD_NOFILE="+limit)
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("child budget check: %v %s", e, b)
			}
		})
	}
}
