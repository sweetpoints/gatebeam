package composition

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/application/health"
	"gatebeam/internal/modules/deployment/infrastructure/dns"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/deployment/infrastructure/probe"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"net/netip"
	"os"
	"sync"
	"time"
)

// managementTargets reads only the endpoints from the protected role configuration.
func managementTargets(cfg bootstrap.Config) (primary, peer netip.AddrPort, additional []netip.AddrPort, err error) {
	primary, err = netip.ParseAddrPort(cfg.ManagementAPIAddress)
	if err != nil || !primary.Addr().IsPrivate() || primary.Port() == 0 {
		return primary, peer, nil, errors.New("invalid private management API address")
	}
	seen := map[netip.AddrPort]bool{primary: true}
	addresses := cfg.ManagementAPIAdditionalAddresses
	legacyPeer := cfg.ManagementAPIPeerAddress != ""
	if legacyPeer {
		addresses = append([]string{cfg.ManagementAPIPeerAddress}, addresses...)
	}
	for i, raw := range addresses {
		address, e := netip.ParseAddrPort(raw)
		if e != nil || !address.Addr().IsPrivate() || address.Port() == 0 || seen[address] {
			return primary, peer, nil, errors.New("invalid peer management API address")
		}
		seen[address] = true
		if i == 0 && legacyPeer {
			peer = address
		} else {
			additional = append(additional, address)
		}
	}
	return primary, peer, additional, nil
}

// runtimeProtected is process-owned configuration, never a request override.
func runtimeProtected(cfg bootstrap.Config) ([]netip.Prefix, error) {
	address := cfg.ManagementAPIAddress
	if address == "" {
		address = cfg.APIListen
	}
	api, e := netip.ParseAddrPort(address)
	if e != nil || !api.Addr().IsPrivate() || api.Port() == 0 {
		return nil, errors.New("invalid private management API address")
	}
	out := []netip.Prefix{netip.PrefixFrom(api.Addr(), api.Addr().BitLen())}
	for _, raw := range append([]string{cfg.ManagementAPIPeerAddress, cfg.HealthListen}, cfg.ManagementAPIAdditionalAddresses...) {
		if raw == "" {
			continue
		}
		address, e := netip.ParseAddrPort(raw)
		if e != nil || (!address.Addr().IsPrivate() && !address.Addr().IsLoopback()) {
			return nil, errors.New("invalid protected control address")
		}
		out = append(out, netip.PrefixFrom(address.Addr(), address.Addr().BitLen()))
	}
	if cfg.APIPrivateNetwork != "" {
		p, e := netip.ParsePrefix(cfg.APIPrivateNetwork)
		if e != nil || !p.Addr().IsPrivate() {
			return nil, errors.New("invalid private API network")
		}
		// This prefix constrains where the API may bind; it is not a blanket
		// denial of business backends sharing the same GCP VPC subnet.
	}
	for _, v := range cfg.ProtectedNetworks {
		p, e := netip.ParsePrefix(v)
		if e != nil {
			return nil, errors.New("invalid protected network")
		}
		out = append(out, p)
	}
	return out, nil
}
func runWorker(ctx context.Context, cfg bootstrap.Config) error {
	if cfg.DatabaseFile == "" {
		return errors.New("worker database reference required")
	}
	protected, e := runtimeProtected(cfg)
	if e != nil {
		return e
	}
	boot, cancel := context.WithTimeout(ctx, 10*time.Second)
	p, e := postgres.Open(boot, cfg)
	cancel()
	if e != nil {
		return e
	}
	defer p.Close()
	if e = verifyRoleHistory(ctx, cfg, p); e != nil {
		return e
	}
	repo := deploymentpg.NewRuntime(p, jobs.New(p), protected)
	service := health.New(repo, dns.Targets{Protected: protected}, probe.HTTP{})

	componentStatus := newWorkerComponents()
	ctx = withWorkerComponent(ctx, componentStatus, "")
	observeReadiness(ctx, lifecycle.GlobalJobs, func(c context.Context) error {
		if e := componentStatus.readyError(); e != nil {
			return e
		}
		return verifyRoleHistory(c, cfg, p)
	})
	componentCtx, stop := context.WithCancel(ctx)
	defer stop()
	var components sync.WaitGroup
	start := func(name string, run func(context.Context) error) {
		components.Add(1)
		go func() {
			defer components.Done()
			superviseWorkerComponent(withWorkerComponent(componentCtx, componentStatus, name), name, func(c context.Context) error {
				workerComponentReady(c, false)
				e := run(c)
				workerComponentReady(c, false)
				return e
			})
		}()
	}
	start("certificates", func(c context.Context) error { return runMaterialWorker(c, cfg, p, repo) })
	start("local-logs", func(c context.Context) error { return runLogWorker(c, cfg, p) })
	start("history", func(c context.Context) error { return runHistoryWorker(c, cfg, p) })
	start("archive", func(c context.Context) error { return runArchiveWorker(c, cfg, p) })
	start("notification", func(c context.Context) error { return runNotificationWorker(c, cfg, p) })
	start("backup", func(c context.Context) error { return runBackupWorker(c, cfg, p) })
	defer func() {
		stop()
		done := make(chan struct{})
		go func() { components.Wait(); close(done) }()
		wait, cancel := shutdownContext(ctx, 5*time.Second)
		defer cancel()
		select {
		case <-done:
		case <-wait.Done():
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	loop := newWorkerLoop(repo, service, newWorkerDiagnostics(os.Stderr), time.Now)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if roleAccepts(ctx, lifecycle.GlobalJobs) {
				loop.step(ctx)
			}
		}
	}
}

// A component failure is retried within its own loop. It cannot cancel unrelated
// work or induce a process-wide restart during a dependency outage.
func superviseWorkerComponent(ctx context.Context, name string, run func(context.Context) error) {
	var last time.Time
	for ctx.Err() == nil {
		_ = run(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(last) >= time.Minute {
			fmt.Fprintf(os.Stderr, "worker component %s unavailable; retrying\n", name)
			last = time.Now()
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
