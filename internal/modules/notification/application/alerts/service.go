package alerts

import (
	"context"
	"encoding/json"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Event = domain.Event
type Service struct {
	tx     transaction.Runner
	repo   app.Repository
	reader app.PendingReader
}

func New(tx transaction.Runner, r app.Repository, reader app.PendingReader) *Service {
	return &Service{tx, r, reader}
}
func (s *Service) Emit(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return s.repo.ApplyWithin(sc, e) })
}
func (s *Service) EmitWithin(sc transaction.Scope, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	return s.repo.ApplyWithin(sc, e)
}

// Consume drains only supported owner envelopes. Apply and the platform receipt
// share one transaction, so a rollback cannot lose the source event.
func (s *Service) Consume(ctx context.Context) error {
	kinds := []string{"TargetHealthChanged", "TargetDNSChanged", "CertificateRenewalChanged", "CertificateExpiryChanged", "LogRecordsChanged", "IngestionLagChanged", "LogPipelineChanged", "ArchivePipelineChanged", "QueryPipelineChanged"}
	names := []string{"target_health", "target_dns", "certificate_renewal", "certificate_expiry", "log_records", "ingestion_lag", "log_pipeline", "archive_pipeline", "query_pipeline"}
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		events, err := s.reader.PendingWithin(sc, "notification/v1", kinds)
		if err != nil {
			return err
		}
		for _, v := range events {
			var p struct {
				State       string `json:"state"`
				Fingerprint string `json:"fingerprint"`
				LagSeconds  int64  `json:"lag_seconds"`
			}
			if v.Schema != 1 || json.Unmarshal(v.Payload, &p) != nil {
				return domain.ErrInvalid
			}
			kind := ""
			for i, k := range kinds {
				if v.Type == k {
					kind = names[i]
				}
			}
			e := Event{ID: v.ID, Kind: kind, ResourceID: v.AggregateID, Fingerprint: p.Fingerprint, Version: v.Version, State: p.State, LagSeconds: p.LagSeconds}
			if err = s.EmitWithin(sc, e); err != nil {
				return err
			}
		}
		return nil
	})
}
