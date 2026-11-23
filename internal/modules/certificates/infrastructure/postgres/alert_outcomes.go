package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/outbox"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"time"
)

// alertOutcome runs only after the owning use case has fenced its source result.
// Its state row and outbox envelope commit with that result in the same Scope.
func alertOutcome(sc transaction.Scope, kind, resource, fingerprint, state string, lag int64) error {
	var event outbox.Event
	err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		var old string
		key := kind + "/" + resource + "/" + fingerprint
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "certificates/outcome/"+key); e != nil {
			return e
		}
		err := tx.QueryRow(ctx, `SELECT version,state FROM certificates_alert_outcomes WHERE kind=$1 AND resource_id=$2 AND fingerprint=$3 FOR UPDATE`, kind, resource, fingerprint).Scan(&version, &old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if old == state {
			return nil
		}
		version++
		if _, err = tx.Exec(ctx, `INSERT INTO certificates_alert_outcomes(kind,resource_id,fingerprint,version,state) VALUES($1,$2,$3,$4,$5) ON CONFLICT(kind,resource_id,fingerprint) DO UPDATE SET version=excluded.version,state=excluded.state`, kind, resource, fingerprint, version, state); err != nil {
			return err
		}
		body, _ := json.Marshal(struct {
			State       string `json:"state"`
			Fingerprint string `json:"fingerprint"`
			LagSeconds  int64  `json:"lag_seconds"`
		}{state, fingerprint, lag})
		event = outbox.Event{ID: fmt.Sprintf("certificates/%s/%d", key, version), Type: kind, Schema: 1, AggregateID: resource, Version: version, Payload: body}
		return nil
	})
	if err != nil || event.ID == "" {
		return err
	}
	return outbox.New().AppendWithin(sc, event)
}

func (s *Store) ExpiryWithin(sc transaction.Scope, resource string, revision int64, now time.Time) error {
	r, e := s.Read(sc, "spec", resource, revision)
	if e != nil || !r.Enabled {
		return e
	}
	current, e := s.Current(sc, resource, r.Revision)
	if errors.Is(e, domain.ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	state := "resolved"
	if !current.NotAfter.After(now.Add(7 * 24 * time.Hour)) {
		state = "firing"
	}
	return alertOutcome(sc, "CertificateExpiryChanged", resource, fmt.Sprint(r.Revision), state, 0)
}

// Current-spec expiry supplements explicit published historical revisions.
func (s *Store) ExpiryCurrentWithin(sc transaction.Scope, now time.Time) error {
	var specs []struct {
		ID       string
		Revision int64
	}
	if e := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT r.id::text,r.revision FROM certificates_resources r JOIN certificates_attempts a ON a.spec_id=r.id AND a.spec_revision=r.revision WHERE r.kind='spec' AND r.enabled AND a.current_version IS NOT NULL ORDER BY r.id LIMIT 1000`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v struct {
				ID       string
				Revision int64
			}
			if e = rows.Scan(&v.ID, &v.Revision); e != nil {
				return e
			}
			specs = append(specs, v)
		}
		return rows.Err()
	}); e != nil {
		return e
	}
	for _, v := range specs {
		if e := s.ExpiryWithin(sc, v.ID, v.Revision, now); e != nil {
			return e
		}
	}
	return nil
}
