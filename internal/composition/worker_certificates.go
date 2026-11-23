package composition

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/integration/certificateaccess"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/modules/certificates"
	"gatebeam/internal/modules/certificates/infrastructure/lego"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/deployment/infrastructure/cloudflare"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/platform/bootstrap"
	processlife "gatebeam/internal/platform/lifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"os"
	"time"
)

func runMaterialWorker(ctx context.Context, cfg bootstrap.Config, p *pgxpool.Pool, repo *deploymentpg.Runtime) error {
	ranges, e := cloudflare.New("https://api.cloudflare.com/client/v4/ips", &http.Client{Timeout: 5 * time.Second}, time.Hour)
	if e != nil {
		return e
	}
	var lifecycle *certificatematerials.Worker
	if cfg.CertificateIdentityFile != "" {
		return errors.New("worker must not configure a leaf identity")
	}
	if cfg.CertificateProviderIdentityFile != "" {
		sites := ingress.New(p, nil)
		service, e := certificates.NewWorker(p, certificateaccess.Graph{Ingress: sites}, cfg.CertificateProviderIdentityFile, cfg.CertificateRecipient, cfg.ACMEWebRoot, certificates.InternalACME{Recipients: cfg.EncryptionRecipients, Origin: cfg.CAOrigin, TransportTrustFile: cfg.CertificateACMETransportTrustFile, HTTPChallenges: clusterHTTPChallenges(cfg, p)})
		if e != nil {
			return e
		}
		service.SetEvents(deployment.NewEvents(p))
		if e = certificates.ConfigureStatus(service, cfg.CertificateStatusProfilesFile); e != nil {
			return e
		}
		lifecycle = &certificatematerials.Worker{Published: repo, Certificates: service}
	}
	workerComponentReady(ctx, true)
	nextRanges := time.Time{}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if !roleAccepts(ctx, processlife.GlobalJobs) {
			select {
			case <-ctx.Done():
				return nil
			case <-tick.C:
			}
			continue
		}
		now := time.Now()
		if !now.Before(nextRanges) {
			snapshot, e := repo.Snapshot(ctx)
			needed := false
			if e == nil {
				for _, site := range snapshot.Sites {
					if site.Config.Enabled && site.Config.Cloudflare.Mode == "proxied" {
						needed = true
					}
				}
			}
			if needed {
				old, e := repo.Cloudflare(ctx)
				if e == nil {
					fresh, e := ranges.Refresh(ctx, old, now)
					if e == nil {
						e = repo.SaveCloudflare(ctx, fresh)
					}
					if e != nil {
						fmt.Fprintln(os.Stderr, "Cloudflare runtime refresh failed")
					}
				}
			}
			nextRanges = now.Add(5 * time.Minute)
		}
		if lifecycle != nil {
			if e = lifecycle.Step(ctx); e != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "certificate lifecycle refresh deferred")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func clusterHTTPChallenges(cfg bootstrap.Config, p *pgxpool.Pool) lego.HTTPChallenges {
	if cfg.RuntimeProtocol != 1 {
		return nil
	}
	return certificates.NewHTTPChallenges(p, certificatematerials.ChallengeNodes{Nodes: deployment.NewNodes()})
}
