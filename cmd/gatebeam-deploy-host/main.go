// gatebeam-deploy-host is a root-owned one-shot gateway-host command allowlist.
// It installs no daemon and is never copied to business servers.
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
)

func main() {
	values := map[string]*string{}
	for _, name := range []string{"status", "receipt", "dispatch", "execute"} {
		values[name] = flag.String(name, "", "controlled local operation")
	}
	flag.Parse()
	mode, value := "", ""
	for k, v := range values {
		if *v != "" {
			if mode != "" {
				fmt.Fprintln(os.Stderr, "exactly one operation required")
				os.Exit(1)
			}
			mode, value = k, *v
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, e := composition.RunDeploymentHost(ctx, mode, value)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
}
