package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gatebeam/internal/composition"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	contract := flag.Bool("runtime-contract", false, "compiled offline runtime/schema contract; no initialization")
	config := flag.String("config", "", "JSON configuration file")
	previewEdge := flag.Bool("preview-edge", false, "compile/read authorized enrollment artifact reference without activation")
	initializeEdge := flag.Bool("initialize-edge", false, "online authorized first initialization; never ordinary restart")
	exportCapsule := flag.Bool("export-backup-capsule", false, "seal this role backup capsule locally without starting listeners")
	showBootstrap := flag.Bool("show-bootstrap", false, "display initial enrollment once on the local terminal")
	flag.Parse()
	if *contract {
		if json.NewEncoder(os.Stdout).Encode(composition.RuntimeContract()) != nil {
			os.Exit(1)
		}
		return
	}
	cfg, err := bootstrap.Load(*config)
	if err == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if *previewEdge {
			var artifact string
			artifact, err = composition.PreviewEdgeInitialization(ctx, cfg)
			if err == nil {
				err = json.NewEncoder(os.Stdout).Encode(map[string]string{"artifact_id": artifact})
			}
		} else if *initializeEdge {
			err = composition.InitializeEdge(ctx, cfg)
		} else if *exportCapsule {
			err = composition.ExportBackupCapsule(ctx, cfg)
		} else if cfg.Mode == "bootstrap" {
			info, e := os.Stdout.Stat()
			if !*showBootstrap || e != nil || info.Mode()&os.ModeCharDevice == 0 {
				err = composition.ErrBootstrapDisplay
			} else {
				result, e := composition.Bootstrap(ctx, cfg)
				err = e
				if err == nil {
					err = json.NewEncoder(os.Stdout).Encode(result)
				}
			}
		} else {
			err = composition.Run(ctx, cfg.Mode, cfg)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
