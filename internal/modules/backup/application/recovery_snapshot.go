package application

import (
	"gatebeam/internal/modules/backup/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

// RecoveryReceipt preserves delivery/retention history, not evidence that an
// archive has passed a fresh offline Verify. Historical per-file manifests are
// redundant with the remote encrypted artifact and deliberately omitted.
type RecoveryReceipt struct {
	ID           string            `json:"id"`
	Created      time.Time         `json:"created_at"`
	Manifest     ReceiptProvenance `json:"manifest"`
	CipherSHA256 string            `json:"cipher_sha256"`
	Bytes        int64             `json:"bytes"`
}
type ReceiptProvenance struct {
	Version                            int
	ID                                 string
	Created                            time.Time
	Snapshot, Epoch, Schema, Recipient string
	RecipientRecorded                  bool   `json:"recipient_recorded"`
	DetailStatus                       string `json:"detail_status"`
	ArtifactVerification               string `json:"artifact_verification"`
}
type RecoverySnapshotRepository interface {
	RecoveryReceiptsWithin(transaction.Scope) ([]RecoveryReceipt, error)
}

func ExportRecoveryReceiptsWithin(sc transaction.Scope, repo RecoverySnapshotRepository) ([]RecoveryReceipt, error) {
	rows, e := repo.RecoveryReceiptsWithin(sc)
	if e != nil {
		return nil, e
	}
	if len(rows) > domain.MaxRows {
		return nil, domain.ErrInvalid
	}
	for i := range rows {
		r := &rows[i]
		p := &r.Manifest
		if !domain.ValidDigest(r.ID) || !domain.ValidDigest(r.CipherSHA256) || r.Created.IsZero() || r.Bytes <= 0 || p.Version != 1 || p.ID != r.ID || p.Created.IsZero() || !domain.ValidDigest(p.Schema) || !domain.ValidEpoch(p.Epoch) || len(p.Snapshot) == 0 || len(p.Snapshot) > 256 || len(p.Recipient) > 128 {
			return nil, domain.ErrInvalid
		}
		p.RecipientRecorded = p.Recipient != ""
		p.DetailStatus = "omitted_for_recovery"
		p.ArtifactVerification = "required"
	}
	return rows, nil
}
