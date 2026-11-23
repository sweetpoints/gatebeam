// gatebeam-deploy is an explicit operator process, never a running gateway dependency.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gatebeam/internal/composition"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	intent := flag.String("intent", "", "protected request and explicit inventory JSON")
	dry := flag.Bool("dry-run", false, "pure plan to stdout; no DB, client, locks, caches or logs")
	config := flag.String("config", "", "dedicated deployment DB configuration")
	executor := flag.String("executor-instance", "", "current dedicated GCE execution VM resource")
	resume := flag.String("resume", "", "paused batch UUID")
	proofFile := flag.String("proof", "", "protected fencing and completed-operation proof JSON")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var p upgrade.Plan
	var e error
	if *resume == "" || *dry {
		p, e = composition.PlanDeployment(*intent)
	}
	if e == nil && *dry {
		e = json.NewEncoder(os.Stdout).Encode(p)
	} else if e == nil {
		var proof upgrade.RecoveryProof
		if *resume != "" {
			proof, e = composition.ReadDeploymentProof(*proofFile)
		}
		if e == nil {
			e = composition.ExecuteDeployment(ctx, p, *config, *executor, *resume, proof)
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
