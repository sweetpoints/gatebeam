// Package postgres persists PKI state through the caller's transaction only.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/modules/pki/infrastructure/postgres/dbgen"
	platformpg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrImmutableIssuer = errors.New("issuer registration conflicts with immutable metadata")

type Store struct{}

func New() *Store { return &Store{} }
func (*Store) Register(sc transaction.Scope, i domain.Issuer, der []byte) error {
	if err := leafFence(sc, true); err != nil {
		return err
	}
	return platformpg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var quarantined bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pki_restore_quarantine WHERE issuer_id=$1)`, string(i.ID)).Scan(&quarantined); e != nil {
			return e
		}
		if quarantined {
			return ErrImmutableIssuer
		}
		q := dbgen.New(tx)
		_, e := q.RegisterIssuer(ctx, dbgen.RegisterIssuerParams{ID: string(i.ID), Fingerprint: i.Fingerprint, CertificateDer: der, NotBefore: pgtype.Timestamptz{Time: i.NotBefore, Valid: true}, NotAfter: pgtype.Timestamptz{Time: i.NotAfter, Valid: true}})
		if e != nil {
			return e
		}
		row, e := q.ReadIssuer(ctx, string(i.ID))
		if e != nil {
			return e
		}
		if row.Fingerprint != i.Fingerprint || !bytes.Equal(row.CertificateDer, der) || !row.NotBefore.Time.Equal(i.NotBefore) || !row.NotAfter.Time.Equal(i.NotAfter) {
			return ErrImmutableIssuer
		}
		// Fill all legacy public metadata, including retired issuers: no private
		// key is needed. The bounded refresh fails closed on malformed DER.
		rows, e := tx.Query(ctx, `SELECT id,certificate_der FROM pki_issuers WHERE key_fingerprint IS NULL ORDER BY id LIMIT 1025`)
		if e != nil {
			return e
		}
		type pending struct {
			id  string
			der []byte
		}
		var entries []pending
		for rows.Next() {
			var p pending
			if e = rows.Scan(&p.id, &p.der); e != nil {
				rows.Close()
				return e
			}
			entries = append(entries, p)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if len(entries) > 1024 {
			return ErrImmutableIssuer
		}
		for _, p := range entries {
			cert, e := x509.ParseCertificate(p.der)
			if e != nil {
				return ErrImmutableIssuer
			}
			digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			result, e := tx.Exec(ctx, `UPDATE pki_issuers SET key_fingerprint=$1 WHERE id=$2 AND certificate_der=$3 AND key_fingerprint IS NULL`, hex.EncodeToString(digest[:]), p.id, p.der)
			if e != nil {
				return e
			}
			if result.RowsAffected() != 1 {
				return ErrImmutableIssuer
			}
		}
		return nil
	})
}
func (*Store) ReserveSerial(sc transaction.Scope, issuer domain.IssuerID, serial domain.Serial) error {
	return platformpg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		return dbgen.New(tx).ReserveSerial(ctx, dbgen.ReserveSerialParams{IssuerID: string(issuer), Serial: string(serial)})
	})
}

// Reader exposes public metadata without a signer or write methods.
type Reader struct{ db dbgen.DBTX }

func NewReader(db dbgen.DBTX) *Reader { return &Reader{db: db} }
func (r *Reader) ReadIssuer(ctx context.Context, id domain.IssuerID) (domain.Issuer, error) {
	row, e := dbgen.New(r.db).ReadIssuer(ctx, string(id))
	if e != nil {
		return domain.Issuer{}, e
	}
	return domain.Issuer{ID: domain.IssuerID(row.ID), Fingerprint: row.Fingerprint, NotBefore: row.NotBefore.Time, NotAfter: row.NotAfter.Time}, nil
}
