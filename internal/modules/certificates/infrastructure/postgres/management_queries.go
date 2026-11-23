package postgres

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
)

func finite(t pgtype.Timestamptz) *time.Time {
	if !t.Valid || t.InfinityModifier != pgtype.Finite {
		return nil
	}
	v := t.Time
	return &v
}
func (*Store) Lifecycle(sc transaction.Scope, r app.Resource) (out app.Lifecycle, err error) {
	out.Versions = []app.Version{}
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		prep, e := q.CertificatePreparationMetadata(c, dbgen.CertificatePreparationMetadataParams{Kind: r.Kind, ID: id(r.ID), Revision: r.Revision})
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil {
			out.PreparationFailures = int(prep.Failures)
			out.PreparationNextAttempt = finite(prep.NextAttempt)
			out.Preparing = prep.LeaseUntil.Valid && prep.LeaseUntil.Time.After(time.Now())
		}
		if r.Kind != "spec" {
			return nil
		}
		rows, e := q.CertificateVersionsMetadata(c, id(r.ID))
		if e != nil {
			return e
		}
		for _, b := range rows {
			var v app.Version
			if e = json.Unmarshal(b, &v); e != nil {
				return e
			}
			out.Versions = append(out.Versions, v)
		}
		a, e := q.CertificateAttemptMetadata(c, dbgen.CertificateAttemptMetadataParams{SpecID: id(r.ID), SpecRevision: r.Revision})
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		out.CurrentVersion = a.CurrentVersion
		out.Failures = int(a.Failures)
		out.NextAttempt = finite(a.NextAttempt)
		out.Preparing = out.Preparing || (a.LeaseUntil.Valid && a.LeaseUntil.Time.After(time.Now()))
		return nil
	})
	return
}
