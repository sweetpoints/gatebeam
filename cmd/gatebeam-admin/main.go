// gatebeam-admin is a local operator command; it has no listener.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gatebeam/internal/composition"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	op := flag.String("operation", "", "prepare-role, prepare-management, inspect-boot, validate-node, provision-node, verify-storage, render-node, register-node, activate-nodes, rewrap-role, verify-role, map-legacy-archives")
	config := flag.String("config", "", "local role/operator config")
	request := flag.String("request", "", "protected local JSON input")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	out, e := composition.OperatorOperation(ctx, *op, *config, *request)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e = json.NewEncoder(os.Stdout).Encode(out); e != nil {
		os.Exit(1)
	}
}
