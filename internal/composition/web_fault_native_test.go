//go:build integration && native

package composition

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/publication"
	"gatebeam/internal/modules/deployment"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	runtimebootstrap "gatebeam/internal/modules/deployment/infrastructure/bootstrap"
	"gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Only this cross-compiled test harness has an injected process port. Every
// validation, successful activation, observation and restore uses real Nginx.
// Production binaries contain neither the fault flag nor this assembly.
type webFaultProcess struct {
	*nginx.Process
	armed bool
}

func (p *webFaultProcess) Activate(ctx context.Context, version string) error {
	if !p.armed {
		return p.Process.Activate(ctx, version)
	}
	mode, _ := os.ReadFile("/control/fault")
	if string(mode) == "block_restore" {
		_ = os.Remove("/control/fault")
		return errors.New("test-only injected restore transport error")
	}
	if e := p.Process.Activate(ctx, version); e != nil {
		return e
	}
	switch string(mode) {
	case "restored":
		_ = os.Remove("/control/fault")
		return errors.New("test-only injected post-activation observation transport error")
	case "restore_failed":
		_ = os.Remove("/control/fault")
		_ = os.WriteFile("/control/fault", []byte("block_restore"), 0666)
		return errors.New("test-only injected post-activation observation transport error")
	}
	return nil
}

func TestWebFaultEdge(t *testing.T) {
	if os.Getenv("GATEBEAM_WEB_FAULT_EDGE") != "1" {
		t.Skip("explicit owned native browser harness only")
	}
	started := time.Now()
	cfg, e := bootstrap.Load("/fixture/edge.json")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	pool, e := postgres.Open(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	catalog := &ingressaccess.Catalog{}
	access := identity.NewAccess(pool, catalog)
	sites := ingress.New(pool, ingressaccess.Authorizer{Identity: access})
	catalog.Ingress = sites
	store := jobs.New(pool)
	coordinator := publication.New(postgres.NewRunner(pool), access, sites, publication.UnavailableMaterials{}, deployment.New(), store, audit.New(), identifiers.Generator{})
	api := netip.MustParseAddrPort(cfg.ManagementAPIAddress)
	protected := []netip.Prefix{netip.PrefixFrom(api.Addr(), api.Addr().BitLen())}
	source := &runtimebootstrap.Source{Bindings: deploymentpg.NewRuntime(pool, store, protected), Domain: cfg.ManagementDomain, CertificateFile: cfg.ManagementCertificateFile, KeyFile: cfg.ManagementKeyFile, TrustFile: cfg.ManagementTrustFile, APIAddress: api, LogDirectory: filepath.Join(cfg.EdgeRoot, "logs"), ProtectedNetworks: protected}
	disk, e := filesystem.New(cfg.EdgeRoot)
	if e != nil {
		t.Fatal(e)
	}
	native, e := nginx.NewProcess("/usr/sbin/nginx", cfg.EdgeRoot)
	if e != nil {
		t.Fatal(e)
	}
	process := &webFaultProcess{Process: native}
	compiler := nginx.Compiler{}
	supervisor := func(j jobs.Job) (*edge.Supervisor, *publication.Execution) {
		execution := publication.NewExecution(coordinator, store, j, source, compiler)
		return edge.NewSupervisor(process, disk, disk, compiler, execution), execution
	}
	recovery, _ := supervisor(jobs.Job{})
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = process.Stop(stop)
	}()
	if _, e = recovery.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	process.armed = true
	if e = os.WriteFile("/control/ready", []byte("ready"), 0666); e != nil {
		t.Fatal(e)
	}
	t.Logf("owned browser fault edge recovered actual native baseline, elapsed=%s", time.Since(started).Round(time.Millisecond))
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if _, e := os.Stat("/control/recover"); e == nil {
			_ = os.Remove("/control/recover")
			if _, e = recovery.Recover(ctx); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile("/control/recovered", []byte("recovered"), 0666); e != nil {
				t.Fatal(e)
			}
		}
		job, e := store.ClaimKinds(ctx, "owned-web-fault-edge", time.Minute, []string{"deployment.apply"})
		if e != nil {
			continue
		}
		var payload struct {
			ReleaseID string `json:"release_id"`
		}
		if json.Unmarshal(job.Payload, &payload) != nil || payload.ReleaseID == "" {
			t.Fatal("invalid owned fixture job")
		}
		supervisor, execution := supervisor(job)
		result, e := supervisor.Apply(ctx, payload.ReleaseID)
		if e != nil {
			if e = execution.RecordFailure(ctx, payload.ReleaseID, result); e != nil {
				t.Fatal(e)
			}
		}
	}
}
