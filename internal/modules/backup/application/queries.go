package application

import (
	"context"
	"errors"
	"gatebeam/internal/modules/backup/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

var ErrDenied = errors.New("backup access denied")

type ActorRef struct {
	UserID                       string
	AuthVersion                  int64
	CredentialKind, CredentialID string
}
type Record struct {
	ID                   string    `json:"id"`
	Created              time.Time `json:"created_at"`
	Bytes                int64     `json:"bytes"`
	DetailStatus         string    `json:"detail_status"`
	ArtifactVerification string    `json:"artifact_verification"`
}

// SafeReport is a local command receipt, never proof of business activation.
type SafeReport = domain.SafeReport

type QuerySecurity interface {
	RequireWithin(transaction.Scope, ActorRef) error
}
type QueryRepository interface {
	RecordsWithin(transaction.Scope, int, int) ([]Record, error)
}
type ReportReader interface {
	Latest(context.Context) (*SafeReport, error)
}
type Queries struct {
	Tx       transaction.Runner
	Security QuerySecurity
	Repo     QueryRepository
	Reports  ReportReader
}
type View struct {
	Items        []Record    `json:"items"`
	Report       *SafeReport `json:"local_report"`
	ReportStatus string      `json:"report_status"`
}

func (q *Queries) List(ctx context.Context, a ActorRef, limit, offset int) (out View, err error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return out, errors.New("invalid page")
	}
	ctx, c := context.WithTimeout(ctx, 5*time.Second)
	defer c()
	out.Items = []Record{}
	out.ReportStatus = "unavailable"
	err = q.Tx.Within(ctx, func(sc transaction.Scope) error {
		if e := q.Security.RequireWithin(sc, a); e != nil {
			return e
		}
		rows, e := q.Repo.RecordsWithin(sc, limit, offset)
		if e != nil {
			return e
		}
		out.Items = append(out.Items, rows...)
		if q.Reports != nil {
			out.Report, e = q.Reports.Latest(ctx)
			if e != nil {
				return e
			}
			if out.Report != nil {
				out.ReportStatus = "recorded"
			}
		}
		return nil
	})
	return
}
