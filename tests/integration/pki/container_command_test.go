//go:build integration

package pki_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestContainerPreparationDoesNotExtendFunctionalCommandDeadlines(t *testing.T) {
	for _, execution := range []string{"native", "software-emulated-vm"} {
		t.Run(execution, func(t *testing.T) {
			t.Setenv("GATEBEAM_ACCEPTANCE_EXECUTION", execution)
			for _, operation := range []string{"run", "start", "restart", "exec", "stop", "port", "inspect", "network", "logs"} {
				t.Run(operation, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						ctx, cancel := containerCommandContext(t.Context(), operation)
						defer cancel()
						started := time.Now()
						time.Sleep(13 * time.Second)
						preparing := execution == "software-emulated-vm" && (operation == "run" || operation == "start" || operation == "restart")
						if preparing {
							if ctx.Err() != nil {
								t.Fatal("software container preparation was killed by the functional-command deadline", ctx.Err())
							}
							<-ctx.Done()
							if time.Since(started) != 144*time.Second {
								t.Fatal("preparation did not retain its finite software aggregate bound", time.Since(started))
							}
						}
						if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
							t.Fatal("a native or functional command lost its original deadline", ctx.Err())
						}
					})
				})
			}
		})
	}
}

func TestContainerPreparationHonorsParentCancellation(t *testing.T) {
	t.Setenv("GATEBEAM_ACCEPTANCE_EXECUTION", "software-emulated-vm")
	synctest.Test(t, func(t *testing.T) {
		parent, cancelParent := context.WithCancel(t.Context())
		ctx, cancel := containerCommandContext(parent, "run")
		defer cancel()
		cancelParent()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("container preparation ignored parent cancellation", ctx.Err())
		}
	})
}
