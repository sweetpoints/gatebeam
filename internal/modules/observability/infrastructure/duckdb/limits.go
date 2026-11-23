package duckdb

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// 4096 verified inherited files, up to 4096 DuckDB reopenings and 4096
// descriptors reserved for runtime/extension work. This is a bounded engineering
// allocation, not a measured optimum; memory, PID and scan limits are separate.
const RequiredOpenFiles = 12288

// CheckOpenFileBudget checks the effective exec-child limit. Go may raise its
// own soft RLIMIT_NOFILE while restoring the original limit for exec children,
// so checking only this process's syscall.Getrlimit would give a false pass.
// The shell command is fixed and takes no user input or credentials.
func CheckOpenFileBudget(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "/bin/sh", "-c", "ulimit -Sn").Output()
	n, parse := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if e != nil || parse != nil || n < RequiredOpenFiles {
		return errors.New("query child open-file limit below required 12288")
	}
	return nil
}
