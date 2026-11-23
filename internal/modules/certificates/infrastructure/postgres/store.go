// Package postgres persists only certificate-owned aggregates using explicit scopes.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/modules/certificates/infrastructure/postgres/dbgen"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
)

type Store struct{ metadataOnly, publicOnly bool }

func New() *Store               { return &Store{} }
func NewMaterialReader() *Store { return &Store{metadataOnly: true} }
func NewPublicReader() *Store   { return &Store{metadataOnly: true, publicOnly: true} }
func id(v string) pgtype.UUID   { var out pgtype.UUID; _ = out.Scan(v); return out }
func use(sc transaction.Scope, fn func(context.Context, *dbgen.Queries) error) error {
	return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		e := fn(ctx, dbgen.New(tx))
		if errors.Is(e, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		var pe *pgconn.PgError
		if errors.As(e, &pe) {
			switch pe.Code {
			case "23505":
				return domain.ErrConflict
			case "23503", "23514", "22P02":
				return domain.ErrInvalid
			}
		}
		return e
	})
}
func (*Store) ReadLock(sc transaction.Scope) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { return q.CertificateReadLock(c) })
}
func (*Store) WriteLock(sc transaction.Scope) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error { return q.CertificateWriteLock(c) })
}
func (store *Store) Read(sc transaction.Scope, kind, key string, revision int64) (out app.Record, err error) {
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		if store.metadataOnly {
			r, e := q.CertificateResourceMetadata(c, dbgen.CertificateResourceMetadataParams{Kind: kind, Column2: id(key), Column3: revision})
			out = app.Record{Resource: app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body}, PEM: r.Pem}
			return e
		}
		r, e := q.CertificateResource(c, dbgen.CertificateResourceParams{Kind: kind, Column2: id(key), Column3: revision})
		out = app.Record{Resource: app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body}, PEM: r.Pem, Secret: r.Secret}
		return e
	})
	if err == nil && !store.metadataOnly && (kind == "account" || kind == "credential") {
		err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			var cipher []byte
			e := tx.QueryRow(ctx, `SELECT ciphertext FROM certificates_provider_envelopes WHERE kind=$1 AND id=$2 AND revision=$3`, kind, key, out.Revision).Scan(&cipher)
			if e == pgx.ErrNoRows {
				return nil
			}
			if e == nil {
				out.Secret = cipher
			}
			return e
		})
	}
	return
}
func (*Store) Save(sc transaction.Scope, r app.Record, expected int64) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		if r.Revision != expected+1 {
			return domain.ErrConflict
		}
		if expected == 0 {
			if e := q.CertificateCreate(c, dbgen.CertificateCreateParams{Kind: r.Kind, ID: id(r.ID), Enabled: r.Enabled}); e != nil {
				return e
			}
		} else {
			n, e := q.CertificateUpdate(c, dbgen.CertificateUpdateParams{Kind: r.Kind, ID: id(r.ID), Revision: expected, Enabled: r.Enabled})
			if e != nil {
				return e
			}
			if n != 1 {
				return domain.ErrConflict
			}
		}
		return q.CertificateRevision(c, dbgen.CertificateRevisionParams{Kind: r.Kind, ID: id(r.ID), Revision: r.Revision, Body: r.Body, Pem: append([]byte{}, r.PEM...), Secret: append([]byte{}, r.Secret...)})
	})
}
func (store *Store) Specs(sc transaction.Scope) (out []app.Record, err error) {
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		if store.metadataOnly {
			rows, e := q.CertificateSpecsMetadata(c)
			for _, r := range rows {
				out = append(out, app.Record{Resource: app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body}})
			}
			return e
		}
		rows, e := q.CertificateSpecs(c)
		for _, r := range rows {
			out = append(out, app.Record{Resource: app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body}, PEM: r.Pem, Secret: r.Secret})
		}
		return e
	})
	return
}
func (store *Store) Current(sc transaction.Scope, key string, revision int64) (out app.StoredVersion, err error) {
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		if store.publicOnly {
			r, e := q.CertificateCurrentMetadata(c, dbgen.CertificateCurrentMetadataParams{SpecID: id(key), SpecRevision: revision})
			if e != nil {
				return e
			}
			out.CertificatePEM = r.CertificatePem
			return json.Unmarshal(r.Body, &out.Version)
		}
		r, e := q.CertificateCurrent(c, dbgen.CertificateCurrentParams{SpecID: id(key), SpecRevision: revision})
		if e != nil {
			return e
		}
		out.CertificatePEM = r.CertificatePem
		out.EncryptedKey = r.EncryptedKey
		return json.Unmarshal(r.Body, &out.Version)
	})
	return
}
func (*Store) Claim(sc transaction.Scope, key string, revision int64, token string, until time.Time) (out domain.Attempt, err error) {
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		if e := q.CertificateLeaseCreate(c, id(key)); e != nil {
			return e
		}
		n, e := q.CertificateLeaseClaim(c, dbgen.CertificateLeaseClaimParams{SpecID: id(key), Revision: revision, Token: token, LeaseUntil: pgtype.Timestamptz{Time: until, Valid: true}})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		if e := q.CertificateAttemptCreate(c, dbgen.CertificateAttemptCreateParams{SpecID: id(key), SpecRevision: revision}); e != nil {
			return e
		}
		r, e := q.CertificateClaim(c, dbgen.CertificateClaimParams{SpecID: id(key), SpecRevision: revision, Token: token, LeaseUntil: pgtype.Timestamptz{Time: until, Valid: true}})
		if errors.Is(e, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		out = domain.Attempt{Failures: int(r.Failures), NextAttempt: r.NextAttempt.Time}
		return e
	})
	return
}
func (*Store) Commit(sc transaction.Scope, w app.Work, v app.StoredVersion) error {
	err := use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.CertificateLeaseRelease(c, dbgen.CertificateLeaseReleaseParams{SpecID: id(w.Spec.ID), Revision: w.Spec.Revision, Token: w.Token, RequireValid: true})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		body, e := json.Marshal(v.Version)
		if e != nil {
			return e
		}
		if e = q.CertificateVersion(c, dbgen.CertificateVersionParams{ID: id(v.ID), SpecID: id(v.SpecID), SpecRevision: v.SpecRevision, Body: body, CertificatePem: v.CertificatePEM, EncryptedKey: v.EncryptedKey}); e != nil {
			return e
		}
		n, e = q.CertificateCommit(c, dbgen.CertificateCommitParams{SpecID: id(w.Spec.ID), SpecRevision: w.Spec.Revision, Token: w.Token, CurrentVersion: id(v.ID)})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Manual imports commit immutable material under the management capability.
	// They are not automatic renewal attempts and must not mutate the worker
	// renewal-outcome stream. Expiry monitoring remains an independent worker.
	var spec domain.Spec
	if json.Unmarshal(w.Spec.Body, &spec) == nil && spec.Method == "import" {
		return nil
	}
	return alertOutcome(sc, "CertificateRenewalChanged", w.Spec.ID, fmt.Sprint(w.Spec.Revision), "resolved", 0)
}
func (*Store) Fail(sc transaction.Scope, w app.Work, a domain.Attempt) error {
	err := use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.CertificateLeaseRelease(c, dbgen.CertificateLeaseReleaseParams{SpecID: id(w.Spec.ID), Revision: w.Spec.Revision, Token: w.Token, RequireValid: false})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		n, e = q.CertificateFailure(c, dbgen.CertificateFailureParams{SpecID: id(w.Spec.ID), SpecRevision: w.Spec.Revision, Token: w.Token, Failures: int32(a.Failures), NextAttempt: pgtype.Timestamptz{Time: a.NextAttempt, Valid: true}})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return alertOutcome(sc, "CertificateRenewalChanged", w.Spec.ID, fmt.Sprint(w.Spec.Revision), "firing", 0)
}
func (store *Store) List(sc transaction.Scope, kind string) (out []app.Record, err error) {
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		if store.metadataOnly {
			rows, e := q.CertificateListMetadata(c, kind)
			for _, r := range rows {
				out = append(out, app.Record{Resource: app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body}})
			}
			return e
		}
		rows, e := q.CertificateResources(c, kind)
		for _, r := range rows {
			out = append(out, app.Record{Resource: app.Resource{Kind: r.Kind, ID: r.RID, Revision: r.Revision, Enabled: r.Enabled, Body: r.Body}, PEM: r.Pem, Secret: r.Secret})
		}
		return e
	})
	return
}
func (*Store) Enable(sc transaction.Scope, kind, key string, revision int64, enabled bool) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.CertificateEnable(c, dbgen.CertificateEnableParams{Kind: kind, ID: id(key), Revision: revision, Enabled: enabled})
		if e != nil {
			return e
		}
		if n != 1 {
			return domain.ErrConflict
		}
		return nil
	})
}
func (*Store) Status(sc transaction.Scope, key string, revision int64, profile string) (out app.StatusAttestation, err error) {
	err = use(sc, func(c context.Context, q *dbgen.Queries) error {
		body, e := q.CertificateStatus(c, dbgen.CertificateStatusParams{TrustID: id(key), TrustRevision: revision, ProfileDigest: profile})
		if e != nil {
			return e
		}
		return json.Unmarshal(body, &out)
	})
	return
}
func (*Store) SaveStatus(sc transaction.Scope, key string, revision int64, v app.StatusAttestation) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		body, e := json.Marshal(v)
		if e != nil {
			return e
		}
		return q.CertificateStatusSave(c, dbgen.CertificateStatusSaveParams{TrustID: id(key), TrustRevision: revision, Generation: v.Generation, ProfileDigest: v.ProfileDigest, Body: body})
	})
}
