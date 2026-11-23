//go:build integration

package multinode

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func ProcessMain() bool {
	if os.Getenv("GATEBEAM_TEST_BACKEND") == "1" {
		if e := RunBackend(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("GATEBEAM_TEST_LOG_FSYNC") == "1" {
		if e := FsyncLogs(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Println("{}")
		os.Exit(0)
	}
	if raw := os.Getenv("GATEBEAM_TEST_OWNER_CONTROL"); raw != "" {
		b, e := OwnerControl(raw)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		fmt.Println(string(b))
		os.Exit(0)
	}
	if path := os.Getenv("GATEBEAM_TEST_TCP_ROUTES"); path != "" {
		if e := RouterMain(path); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("GATEBEAM_CAPABILITY_PROBE") == "1" {
		for _, path := range os.Args[1:] {
			if strings.HasPrefix(path, "tcp:") {
				conn, e := net.DialTimeout("tcp", strings.TrimPrefix(path, "tcp:"), time.Second)
				if e == nil {
					conn.Close()
					os.Exit(1)
				}
				continue
			}
			// Unix sockets cannot be opened as regular files. Any present
			// inode is an exposure; only a typed absence proves isolation.
			if strings.HasSuffix(path, ".sock") {
				_, e := os.Lstat(path)
				if e == nil {
					os.Exit(1)
				}
				if !errors.Is(e, os.ErrNotExist) {
					fmt.Fprintln(os.Stderr, "socket absence not proved:", e)
					os.Exit(2)
				}
				continue
			}
			f, e := os.Open(path)
			if e == nil {
				f.Close()
				os.Exit(1)
			}
			if !errors.Is(e, os.ErrNotExist) && !errors.Is(e, os.ErrPermission) {
				fmt.Fprintln(os.Stderr, "unexpected capability probe error:", e)
				os.Exit(2)
			}
		}
		fmt.Println("negative capabilities denied")
		return true
	}
	return false
}
