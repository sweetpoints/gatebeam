package composition

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	backuppg "gatebeam/internal/modules/backup/infrastructure/postgres"
	"gatebeam/internal/modules/backup/infrastructure/reports"
	backups3 "gatebeam/internal/modules/backup/infrastructure/s3"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/objectstore"
	"gatebeam/internal/platform/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"time"
)

func ExportBackupCapsule(ctx context.Context, c bootstrap.Config) error {
	if bootstrap.ValidateCapabilities(c.Mode, c) != nil || c.BackupRecipient == "" || c.BackupCapsuleDirectory == "" {
		return errors.New("backup capsule configuration unavailable")
	}
	paths := map[string]string{}
	add := func(n, p string) {
		if p != "" {
			paths[n] = p
		}
	}
	switch c.Mode {
	case "api":
		add("identity.agekey", c.IdentityFile)
		add("api-tls.pem", c.APITLSCertificateFile)
		add("api-tls.key", c.APITLSKeyFile)
		add("api-trust.pem", c.APITLSTrustFile)
		add("api-client.crl", c.APITLSCRLFile)
	case "ca":
		add("identity.agekey", c.CAIdentityFile)
		add("issuer.age", c.CASignerFile)
		add("issuer.pem", c.CACertificateFile)
		add("root.pem", c.CARootFile)
		add("root.crl.der", c.CARootCRLFile)
		add("root-ocsp.pem", c.CARootOCSPCertificateFile)
		add("root-ocsp.age", c.CARootOCSPSignerFile)
		add("tls.pem", c.CATLSCertificateFile)
		add("tls.key", c.CATLSKeyFile)
	case "edge":
		add("materials.agekey", c.CertificateIdentityFile)
		add("management.pem", c.ManagementCertificateFile)
		add("management.key", c.ManagementKeyFile)
		add("management-trust.pem", c.ManagementTrustFile)
		add("status-profiles.json", c.CertificateStatusProfilesFile)
		add("api-client.pem", c.ManagementAPIClientCertificateFile)
		add("api-client.key", c.ManagementAPIClientKeyFile)
		add("api-trust.pem", c.ManagementAPITrustFile)
		add("management-upstreams.json", c.ManagementAPIStateFile)
	case "worker":
		add("provider.agekey", c.CertificateProviderIdentityFile)
		add("notification.agekey", c.NotificationIdentityFile)
		add("acme-transport.pem", c.CertificateACMETransportTrustFile)
	default:
		return errors.New("role cannot export backup keys")
	}
	if c.PrivateTLSRenewal != nil {
		add("acme-eab.json", c.PrivateTLSRenewal.EABFile)
		if _, e := os.Lstat(privateTLSOutput(c)); e == nil {
			add("renewed-tls.pem", privateTLSOutput(c))
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	for _, public := range c.EncryptionRecipients {
		for _, recipient := range public {
			if recipient == c.BackupRecipient {
				return errors.New("backup recovery recipient must be offline")
			}
		}
	}
	if c.RuntimeProtocol == 1 {
		return archive.ExportNodeCapsule(ctx, c.BackupCapsuleDirectory, c.Mode, c.BackupEpoch, c.BackupRecipient, c.NodeID, c.NodeEpoch, paths)
	}
	return archive.ExportCapsule(ctx, c.BackupCapsuleDirectory, c.Mode, c.BackupEpoch, c.BackupRecipient, paths)
}
func exportBackup(ctx context.Context, c bootstrap.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	p, e := postgres.Open(ctx, c)
	if e != nil {
		return e
	}
	defer p.Close()
	_, e = (recovery.Snapshot{DB: p, Capsules: c.BackupCapsuleDirectory, Epoch: c.BackupEpoch, Recipient: c.BackupRecipient, Spool: c.BackupSpoolDirectory}).Export(ctx)
	return e
}
func restoreBackup(ctx context.Context, c bootstrap.Config) (result error) {
	safe := application.SafeReport{ID: uuid.NewString(), At: time.Now().UTC(), Stage: "configuration", Outcome: "failed", Cause: "configuration_unavailable"}
	defer func() {
		if c.RecoveryReportDirectory != "" {
			if e := (reports.Store{Directory: c.RecoveryReportDirectory}).Write(safe); e != nil {
				result = errors.Join(result, errors.New("safe recovery report unavailable"))
			}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	local, e := recovery.LocalAdminConfig(c.DatabaseFile)
	if e != nil {
		return e
	}
	p, e := pgxpool.NewWithConfig(ctx, local)
	if e != nil {
		return recovery.ErrRecovery
	}
	defer p.Close()
	target := &recovery.Destination{Admin: p, Directory: c.RecoveryDirectory, Identity: c.RecoveryIdentityFile}
	r := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	safe.Stage = "verify"
	safe.Cause = "artifact_verification_failed"
	report, e := r.Verify(ctx, c.RecoverySource, c.RecoveryIdentityFile)
	if e != nil {
		return e
	}
	safe.ArtifactID = report.Manifest.ID
	safe.Stage = "stage"
	safe.Cause = "isolated_stage_failed"
	if e = r.Restore(ctx, report, application.Conservative); e != nil {
		return e
	}
	safe.Outcome = "isolated_staged"
	safe.Cause = "manual_activation_required"
	fmt.Fprintf(os.Stdout, "isolated recovery staged: database=%s directory=%s; manual rebootstrap and trust rotation required\n", target.Database, target.Output)
	return nil
}
func backupService(c bootstrap.Config, p *pgxpool.Pool) (*application.Service, application.Policy, error) {
	policy := application.Policy{Retain: time.Duration(c.BackupRetentionDays) * 24 * time.Hour, MaxAge: time.Duration(c.BackupMaxAgeMinutes) * time.Minute}
	if policy.Validate() != nil {
		return nil, policy, errors.New("invalid backup retention/freshness policy")
	}
	cfg, e := objectstore.LoadConfig(c.BackupCredentialsFile)
	if e != nil {
		return nil, policy, e
	}
	store, e := backups3.New(cfg)
	if e != nil {
		return nil, policy, e
	}
	return &application.Service{Source: archive.Source{Directory: c.BackupSpoolDirectory}, Objects: store, Catalog: backuppg.Catalog{DB: p}}, policy, nil
}
func runBackupWorker(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) error {
	if c.BackupCredentialsFile == "" {
		workerComponentReady(ctx, true)
		<-ctx.Done()
		return nil
	}
	svc, policy, e := backupService(c, p)
	if e != nil {
		return e
	}
	workerComponentReady(ctx, true)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	return backupLoop(ctx, svc, policy, tick.C)
}
func backupLoop(ctx context.Context, svc *application.Service, policy application.Policy, ticks <-chan time.Time) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		var e error
		if roleAccepts(ctx, lifecycle.GlobalJobs) {
			_, e = svc.Create(ctx, policy)
		}
		if e != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, `{"component":"backup_worker","reason":"backup_unavailable"}`)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
		}
	}
}
