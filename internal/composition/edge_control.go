package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/integration/certificateaccess"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/publication"
	"gatebeam/internal/modules/certificates"
	certapp "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/deployment"
	deployapp "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	runtimebootstrap "gatebeam/internal/modules/deployment/infrastructure/bootstrap"
	"gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/deployment/infrastructure/probe"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"gatebeam/internal/modules/pki"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

func runEdgeControl(ctx context.Context, cfg bootstrap.Config, node domain.NodeRef, process *nginx.Process, disk *filesystem.Store, offline *certificatematerials.OfflineStatus) error {
	return runEdgeControlMode(ctx, cfg, node, process, disk, offline, false, nil)
}
func runEdgeControlMode(ctx context.Context, cfg bootstrap.Config, node domain.NodeRef, process *nginx.Process, disk *filesystem.Store, offline *certificatematerials.OfflineStatus, initialize bool, preview *string) error {
	previewStarted := time.Now()
	previewPhase := "configuration"
	previewReported := false
	reportPreview := func() {
		if preview != nil && !previewReported {
			previewReported = true
			// Only a fixed phase and numeric/context metadata leave this path;
			// database errors and private bootstrap material stay unreported.
			fmt.Fprintf(os.Stderr, "gatebeam enrollment preview phase=%s elapsed_ms=%d deadline_expired=%t context_cancelled=%t\n", previewPhase, time.Since(previewStarted).Milliseconds(), errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(ctx.Err(), context.Canceled))
		}
	}
	defer reportPreview()
	if cfg.EdgeRoot == "" || cfg.DatabaseFile == "" || cfg.ManagementDomain == "" || cfg.ManagementCertificateFile == "" || cfg.ManagementKeyFile == "" || cfg.ManagementTrustFile == "" {
		return errors.New("edge bootstrap configuration incomplete")
	}
	api, e := netip.ParseAddrPort(cfg.ManagementAPIAddress)
	if e != nil || !api.Addr().IsPrivate() || (api.Port() != 8080 && cfg.ManagementAPIPeerAddress == "") {
		return errors.New("invalid private management API address")
	}
	protected := []netip.Prefix{netip.PrefixFrom(api.Addr(), api.Addr().BitLen())}
	for _, raw := range []string{cfg.ManagementAPIPeerAddress, cfg.HealthListen} {
		if raw == "" {
			continue
		}
		address, e := netip.ParseAddrPort(raw)
		if e != nil || (!address.Addr().IsPrivate() && !address.Addr().IsLoopback()) {
			return errors.New("invalid protected control address")
		}
		protected = append(protected, netip.PrefixFrom(address.Addr(), address.Addr().BitLen()))
	}
	for _, v := range cfg.ProtectedNetworks {
		p, e := netip.ParsePrefix(v)
		if e != nil {
			return errors.New("invalid protected network")
		}
		protected = append(protected, p)
	}
	if disk == nil && preview == nil {
		disk, e = filesystem.New(cfg.EdgeRoot)
		if e != nil {
			return e
		}
	}
	if process == nil && preview == nil {
		process, e = nginx.NewProcess("/usr/sbin/nginx", cfg.EdgeRoot)
		if e != nil {
			return e
		}
		defer func() {
			stop, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			_ = process.Stop(stop)
		}()
	}
	if cfg.RuntimeProtocol == 1 && cfg.BackupRecipient != "" && preview == nil {
		if e := ExportBackupCapsule(ctx, cfg); e != nil {
			return e
		}
	}
	previewPhase = "database-open"
	boot, cancel := context.WithTimeout(ctx, 10*time.Second)
	pool, e := postgres.Open(boot, cfg)
	cancel()
	if e != nil {
		return e
	}
	defer pool.Close()
	// Capture before pool cleanup can spend time or change the deadline state.
	defer reportPreview()
	readinessCtx, stopReadiness := context.WithCancel(ctx)
	defer stopReadiness()
	observeReadiness(readinessCtx, lifecycle.GlobalJobs, pool.Ping)
	catalog := &ingressaccess.Catalog{}
	access := identity.NewAccess(pool, catalog)
	sites := ingress.New(pool, ingressaccess.Authorizer{Identity: access})
	catalog.Ingress = sites
	store := jobs.New(pool)
	if cfg.CertificateProviderIdentityFile != "" {
		return errors.New("edge must not configure a provider identity")
	}
	previewPhase = "certificate-reader"
	materials := certificates.NewReader(pool)
	if cfg.CertificateIdentityFile != "" {
		materials, e = certificates.NewEdge(pool, certificateaccess.Graph{Ingress: sites}, cfg.CertificateIdentityFile, cfg.CertificateProviderRecipient, cfg.EncryptionRecipients)
		if e != nil {
			return e
		}
	}
	var challenges *certapp.HTTPChallenges
	var challengeFiles certapp.HTTPChallengeFiles
	if cfg.RuntimeProtocol == 1 && cfg.ACMEWebRoot != "" && preview == nil {
		challenges = certificates.NewHTTPChallenges(pool, certificatematerials.ChallengeNodes{Nodes: deployment.NewNodes()})
		challengeFiles, e = certificates.NewHTTPChallengeFiles(cfg.ACMEWebRoot)
		if e != nil {
			return e
		}
		if e = challenges.Sync(ctx, certapp.NodeRef{ID: node.ID, Epoch: node.Epoch}, challengeFiles); e != nil {
			return e
		}
	}
	previewPhase = "distribution"
	if cfg.RuntimeProtocol == 1 && cfg.CertificateIdentityFile != "" {
		if e = certificates.ConfigureNodeDistribution(materials, pool, certificatematerials.NodeAuthority{Nodes: deployment.NewNodes()}, certapp.NodeRef{ID: node.ID, Epoch: node.Epoch}, cfg.CertificateIdentityFile, cfg.CertificateRecipient); e != nil {
			return e
		}
	}
	previewPhase = "status-profile"
	materials.SetLeafStatus(certificatematerials.LeafStatus{Owner: pki.NewMaterialStatus()})
	if e = certificates.ConfigureStatus(materials, cfg.CertificateStatusProfilesFile); e != nil {
		return e
	}
	coordinator := publication.New(postgres.NewRunner(pool), access, sites, certificatematerials.Adapter{Owner: materials, Offline: offline}, deployment.New(), store, audit.New(), identifiers.Generator{})
	coordinator.SetNodes(deployment.NewNodes())
	bindings := deploymentpg.NewRuntime(pool, store, protected)
	source := &runtimebootstrap.Source{ACMEWebRoot: cfg.ACMEWebRoot, Bindings: bindings, Materials: certificatematerials.Adapter{Owner: materials, Offline: offline}, Cloudflare: bindings, Domain: cfg.ManagementDomain, CertificateFile: cfg.ManagementCertificateFile, KeyFile: cfg.ManagementKeyFile, TrustFile: cfg.ManagementTrustFile, APIAddress: api, LogDirectory: filepath.Join(cfg.EdgeRoot, "logs"), ProtectedNetworks: protected}
	if cfg.ManagementAPIPeerAddress != "" {
		source.PeerAPIAddress, e = netip.ParseAddrPort(cfg.ManagementAPIPeerAddress)
		if e != nil || !source.PeerAPIAddress.Addr().IsPrivate() || source.PeerAPIAddress.Port() == 0 {
			return errors.New("invalid peer management API address")
		}
		source.UpstreamName = cfg.ManagementAPIName
		source.UpstreamTrustFile = cfg.ManagementAPITrustFile
		source.UpstreamCertificateFile = cfg.ManagementAPIClientCertificateFile
		source.UpstreamRenewedCertificateFile = privateTLSOutput(cfg)
		source.UpstreamKeyFile = cfg.ManagementAPIClientKeyFile
		source.ManagementStateFile = cfg.ManagementAPIStateFile
	}
	compiler := nginx.Compiler{}
	if preview != nil {
		previewPhase = "artifact-read"
		return postgres.NewRunner(pool).Within(ctx, func(sc transaction.Scope) error {
			_, receipt, err := deployment.New().CurrentVerifiedWithin(sc)
			if err == nil {
				*preview = receipt.ArtifactID
				previewPhase = "transaction-commit"
				return nil
			}
			if !errors.Is(err, domain.ErrNotFound) {
				return err
			}
			snapshot := deployapp.Snapshot{Version: "deployment/v1"}
			previewPhase = "source-read"
			state, err := source.ReadWithin(sc, snapshot)
			if err != nil {
				return err
			}
			snapshot.Version = "bootstrap"
			previewPhase = "compile"
			artifact, err := compiler.Compile(snapshot, state)
			if err == nil {
				*preview = artifact.ID
				previewPhase = "transaction-commit"
			}
			return err
		})
	}

	supervisor := func(j jobs.Job) (*edge.Supervisor, *publication.Execution) {
		execution := publication.NewExecution(coordinator, store, j, source, compiler)
		s := edge.NewSupervisor(process, disk, disk, compiler, execution, edge.RouteVerifier{Probe: probe.HTTP{}, Evidence: bindings})
		if cfg.RuntimeProtocol == 1 {
			execution.SetNode(node, cfg.ImageDigest)
			if initialize {
				s.SetBootStore(initializationBoot{BootStore: disk}, node)
			} else {
				s.SetBootStore(disk, node)
			}
		}
		return s, execution
	}
	recovery, recoveryExecution := supervisor(jobs.Job{})
	if cfg.RuntimeProtocol == 1 {
		if err := postgres.NewRunner(pool).Within(ctx, func(sc transaction.Scope) error {
			return deployment.NewNodes().AuthorizeRuntimeWithin(sc, node, cfg.ImageDigest)
		}); err != nil {
			return err
		}
		if initialize {
			if _, err := os.Lstat(filepath.Join(cfg.EdgeRoot, "boot", "confirmed.json")); !os.IsNotExist(err) {
				return errors.New("initialized or unverified existing boot evidence; use normal restart")
			}
			if err := logfile.InitializeNodeVolume(filepath.Join(cfg.EdgeRoot, "logs"), node.ID); err != nil {
				return err
			}
			_, err := recovery.Recover(ctx)
			return err
		}
		confirmed, err := disk.LoadConfirmed(ctx, node)
		if err != nil {
			return err
		}
		actual, err := process.Observe(ctx)
		if err != nil {
			return err
		}
		if err = recoveryExecution.ReconcileLocal(ctx, confirmed, actual); err != nil && !errors.Is(err, domain.ErrConflict) {
			return err
		}
		// A freshly enrolled node must earn its own real load/verification of
		// the existing published content. No global receipt is copied to it.
		if err = postgres.NewRunner(pool).Within(ctx, func(sc transaction.Scope) error {
			_, err := deployment.NewNodes().CurrentWithin(sc, node)
			if !errors.Is(err, domain.ErrNotFound) {
				return err
			}
			receipt, _, err := deployment.New().CurrentVerifiedWithin(sc)
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			_, err = store.EnqueueTargetWithin(sc, "deployment.node.generation.v1", "enrollment/"+receipt.ID, json.RawMessage(`{"kind":"certificate"}`), jobs.ClaimTarget{NodeID: node.ID, Epoch: node.Epoch})
			return err
		}); err != nil {
			return err
		}
	}
	stopRenewal := startPrivateTLS(ctx, cfg, pool)
	defer stopRenewal()
	// The legacy bridge recovers online. Protocol 1 has already booted before
	// this control connection and must not replace that startup authority.
	if cfg.RuntimeProtocol == 0 {
		if _, e = recovery.Recover(ctx); e != nil {
			return e
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if challenges != nil {
			step, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := challenges.Sync(step, certapp.NodeRef{ID: node.ID, Epoch: node.Epoch}, challengeFiles)
			cancel()
			if err != nil {
				continue
			}
		}
		j, e := disk.Load(ctx)
		if e != nil {
			return e
		}
		if cfg.RuntimeProtocol == 1 && j.ReceiptPending {
			confirmed, err := disk.LoadConfirmed(ctx, node)
			actual, observeErr := process.Observe(ctx)
			if err != nil || observeErr != nil {
				continue
			}
			if err = recoveryExecution.ReconcileLocal(ctx, confirmed, actual); err != nil && !errors.Is(err, domain.ErrConflict) {
				continue
			}
		}
		restricted := false
		if cfg.RuntimeProtocol == 1 {
			currentErr := postgres.NewRunner(pool).Within(ctx, func(sc transaction.Scope) error {
				if err := deployment.NewNodes().AuthorizeRuntimeWithin(sc, node, cfg.ImageDigest); err != nil {
					return err
				}
				current, err := deployment.NewNodes().CurrentWithin(sc, node)
				restricted = err == nil && current.State == "restricted"
				return err
			})
			if currentErr != nil && !errors.Is(currentErr, domain.ErrNotFound) {
				continue
			}
		}
		if j.ReceiptPending || process.PID() == 0 || restricted {
			if _, e = recovery.Recover(ctx); e != nil {
				continue
			}
		}
		claim, cancel := context.WithTimeout(ctx, 3*time.Second)
		var job jobs.Job
		if cfg.RuntimeProtocol == 1 {
			job, e = store.ClaimTargetKinds(claim, node.ID+"/nginx", jobs.ClaimTarget{NodeID: node.ID, Epoch: node.Epoch}, time.Minute, []string{"deployment.node.apply.v1", "deployment.node.generation.v1", "deployment.node.rotate_logs.v1"})
		} else {
			job, e = store.ClaimKinds(claim, "local-edge", time.Minute, []string{"deployment.apply", "deployment.generation", "deployment.rotate_logs"})
		}
		cancel()
		if e != nil {
			continue
		}
		s, execution := supervisor(job)
		switch job.Kind {
		case "deployment.apply", "deployment.node.apply.v1":
			var payload struct {
				ReleaseID string `json:"release_id"`
			}
			if json.Unmarshal(job.Payload, &payload) != nil || payload.ReleaseID == "" {
				continue
			}
			result, e := s.Apply(ctx, payload.ReleaseID)
			if e != nil {
				_ = execution.RecordFailure(ctx, payload.ReleaseID, result)
			} else {
				recordManagementApplied(ctx, disk, node)
			}
		case "deployment.generation", "deployment.node.generation.v1":
			var payload struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(job.Payload, &payload) != nil || !domain.DerivedKind(payload.Kind) {
				continue
			}
			_, err := s.ApplyDerived(ctx, payload.Kind)
			if err == nil {
				recordManagementApplied(ctx, disk, node)
			}
		case "deployment.rotate_logs", "deployment.node.rotate_logs.v1":
			if e = s.RotateLogs(ctx); e == nil {
				done, cancel := context.WithTimeout(ctx, 3*time.Second)
				_ = store.Complete(done, job.ID, job.LeaseToken)
				cancel()
			}
		}
	}
}
