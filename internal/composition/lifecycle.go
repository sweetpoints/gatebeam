package composition

import (
	"context"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"net/http"
	"time"
)

// Legacy bridge modes retain their old launch contract until the independently
// provisioned private health/control endpoints are configured by the operator.
func Run(ctx context.Context, mode string, cfg bootstrap.Config) error {
	if cfg.HealthListen == "" && cfg.ControlSocket == "" {
		return runProcess(ctx, mode, cfg)
	}
	if !bootstrap.SupportedMode(mode) || bootstrap.ValidateCapabilities(mode, cfg) != nil {
		return ErrProcessCapability
	}
	switch mode {
	case "edge", "api", "worker", "ca", "query":
	default:
		return errors.New("health endpoints require a runtime role")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	state := lifecycle.New(time.Now)
	cfg.RuntimeState = state
	cfg.Mode = mode
	state.SetReady(lifecycle.LocalCleanup, true)
	roleCtx, cancel := context.WithCancel(lifecycle.WithState(context.WithoutCancel(ctx), state))
	defer cancel()
	health, e := startRoleHealth(roleCtx, cfg, state)
	if e != nil {
		return e
	}
	defer health.Close()
	defer state.Stop()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			state.BeginDrain(time.Now().Add(drainDuration(cfg)))
		case <-state.Draining():
		case <-watchDone:
			return
		}
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			deadline := state.Snapshot().Deadline
			if !time.Now().Before(deadline) {
				cancel()
				return
			}
			select {
			case <-tick.C:
			case <-watchDone:
				return
			}
		}
	}()
	var err error
	for roleCtx.Err() == nil {
		err = runProcess(roleCtx, mode, cfg)
		if !errors.Is(err, postgres.ErrUnavailable) && !errors.Is(err, ErrManagementUnavailable) {
			break
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-roleCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if roleCtx.Err() != nil && state.Snapshot().Mode == "draining" {
		return nil
	}
	return err
}
func setRoleReady(ctx context.Context, cap string, ready bool) {
	if state := lifecycle.FromContext(ctx); state != nil {
		state.SetReady(cap, ready)
	}
}
func roleAccepts(ctx context.Context, cap string) bool {
	if allowed, ok := workerAdmission(ctx, cap); ok {
		return allowed
	}
	state := lifecycle.FromContext(ctx)
	return state == nil || state.Accepts(cap)
}
func roleAdmission(ctx context.Context, cap string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !roleAccepts(ctx, cap) {
			http.Error(w, "service unavailable", 503)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func observeReadiness(ctx context.Context, cap string, probe func(context.Context) error) {
	state := lifecycle.FromContext(ctx)
	if state == nil {
		return
	}
	check := func() {
		step, cancel := context.WithTimeout(ctx, time.Second)
		e := probe(step)
		cancel()
		state.SetProbeResult(cap, e)
	}
	check()
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				check()
			}
		}
	}()
}
func shutdownContext(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(budget)
	if state := lifecycle.FromContext(ctx); state != nil {
		if d := state.Snapshot().Deadline; !d.IsZero() && d.Before(deadline) {
			deadline = d
		}
	}
	return context.WithDeadline(context.Background(), deadline)
}

func recordManagementApplied(ctx context.Context, disk *filesystem.Store, node domain.NodeRef) {
	state := lifecycle.FromContext(ctx)
	if state == nil {
		return
	}
	bundle, e := disk.LoadConfirmed(ctx, node)
	if e != nil {
		return
	}
	state.SetDetail("artifact_id", bundle.Manifest.ArtifactID)
	state.SetDetail("generation", bundle.Manifest.Generation)
	state.SetDetail("management_config_digest", "")
	if bundle.Plan.Runtime.Management != nil {
		state.SetDetail("management_config_digest", bundle.Plan.Runtime.Management.ConfigurationDigest)
	}
}
