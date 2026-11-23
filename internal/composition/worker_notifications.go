package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/notificationaccess"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/modules/notification"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/lifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"time"
)

// Independent loop: provider timeouts cannot delay health, certificates, archive,
// ingestion or queries, and its claim allowlist cannot steal their jobs.
func runNotificationWorker(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) error {
	if c.NotificationIdentityFile == "" {
		workerComponentReady(ctx, true)
		<-ctx.Done()
		return nil
	}
	if c.NotificationRecipient == "" {
		return errors.New("notification recipient required")
	}
	for _, other := range []string{c.CertificateRecipient, c.CertificateProviderRecipient, c.CARecipient} {
		if other != "" && other == c.NotificationRecipient {
			return errors.New("notification recipient must be dedicated")
		}
	}
	catalog := &ingressaccess.Catalog{}
	access := identity.NewAccess(p, catalog)
	sites := ingress.New(p, nil)
	catalog.Ingress = sites
	security := &notificationaccess.Security{Access: access, Ingress: sites, Background: true}
	alerts, deliveries, err := notification.NewWorker(p, security, c.NotificationIdentityFile, c.NotificationRecipient, c.EncryptionRecipients.Role("notification"))
	if err != nil {
		return err
	}
	workerComponentReady(ctx, true)
	queue := jobs.New(p)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var diagnostic time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if !roleAccepts(ctx, lifecycle.GlobalJobs) {
			continue
		}
		step, done := context.WithTimeout(ctx, 35*time.Second)
		err = alerts.Consume(step)
		if err == nil {
			job, e := queue.ClaimKinds(step, "notification", 40*time.Second, []string{"notification.delivery"})
			if e == nil {
				var payload struct {
					DeliveryID string `json:"delivery_id"`
				}
				if json.Unmarshal(job.Payload, &payload) != nil || payload.DeliveryID == "" {
					err = errors.New("invalid notification job")
				} else {
					err = deliveries.Deliver(step, payload.DeliveryID)
				}
				if err == nil {
					err = queue.Complete(step, job.ID, job.LeaseToken)
				}
			} else if !errors.Is(e, jobs.ErrNoJob) {
				err = e
			}
		}
		if err == nil {
			err = deliveries.Step(step)
		}
		if err != nil && ctx.Err() == nil && time.Since(diagnostic) >= time.Minute {
			fmt.Fprintln(os.Stderr, `{"component":"notification_worker","reason":"delivery_deferred"}`)
			diagnostic = time.Now()
		}
		done()
	}
}
