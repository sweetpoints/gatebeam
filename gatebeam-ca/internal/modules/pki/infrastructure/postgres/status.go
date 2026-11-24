package postgres

import (
	"bytes"
	"context"
	"errors"
	acme "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/modules/pki/infrastructure/postgres/dbgen"
	"gatebeam-ca/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
)

func (*Store) Owner(sc transaction.Scope, issuer domain.IssuerID, serial domain.Serial) (status.Owner, error) {
	var out status.Owner
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.CertificateOwner(c, dbgen.CertificateOwnerParams{IssuerID: string(issuer), Serial: string(serial)})
		out = status.Owner{Names: v.Names, PrincipalID: v.PrincipalID, AccountID: v.AccountID, Directory: v.Directory, OrderID: v.OrderID}
		return e
	})
	return out, e
}
func (*Store) Status(sc transaction.Scope, issuer domain.IssuerID, serial domain.Serial) (status.Record, error) {
	out := status.Record{State: domain.StatusUnknown}
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		v, e := q.CertificateStatus(c, dbgen.CertificateStatusParams{IssuerID: string(issuer), Serial: string(serial)})
		if e != nil {
			return e
		}
		out.State = domain.StatusGood
		if v.RevokedAt.Valid {
			out.State = domain.StatusRevoked
			out.Revocation = domain.Revocation{Serial: serial, Reason: int(v.Reason.Int32), At: v.RevokedAt.Time}
		}
		return nil
	})
	if errors.Is(e, acme.ErrNotFound) {
		e = nil
	}
	return out, e
}
func (*Store) Revoke(sc transaction.Scope, issuer domain.IssuerID, r domain.Revocation) error {
	if err := leafFence(sc, true); err != nil {
		return err
	}
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.InsertRevocation(c, dbgen.InsertRevocationParams{IssuerID: string(issuer), Serial: string(r.Serial), Reason: int32(r.Reason), RevokedAt: pgtype.Timestamptz{Time: r.At, Valid: true}})
		if e == nil && n != 1 {
			return domain.ErrAlreadyRevoked
		}
		return e
	})
}
func (*Store) CRLSnapshot(sc transaction.Scope, issuer domain.IssuerID) (int64, []domain.Revocation, error) {
	var number int64
	var out []domain.Revocation
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		number, e = q.NextCRLNumber(c, string(issuer))
		if e != nil {
			return e
		}
		rows, e := q.ListRevocations(c, string(issuer))
		if e != nil {
			return e
		}
		for _, v := range rows {
			out = append(out, domain.Revocation{Serial: domain.Serial(v.Serial), Reason: int(v.Reason), At: v.RevokedAt.Time})
		}
		return nil
	})
	return number, out, e
}
func (s *Store) ReserveResponder(sc transaction.Scope, issuer domain.IssuerID, serial domain.Serial, der []byte) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		// Serial-specific advisory lock makes registering one shared delegated cert
		// idempotent across concurrent requests without accepting a leaf collision.
		if e := q.LockPrincipalID(c, "gatebeam-ca/pki/responder/"+string(issuer)+"/"+string(serial)); e != nil {
			return e
		}
		existing, e := q.ReadResponder(c, dbgen.ReadResponderParams{IssuerID: string(issuer), Serial: string(serial)})
		if e == nil {
			if !bytes.Equal(existing, der) {
				return status.ErrDenied
			}
			return nil
		}
		// ReadResponder missing is handled without aborting PostgreSQL's transaction.
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e = q.ReserveSerial(c, dbgen.ReserveSerialParams{IssuerID: string(issuer), Serial: string(serial)}); e != nil {
			return e
		}
		return q.InsertResponder(c, dbgen.InsertResponderParams{IssuerID: string(issuer), Serial: string(serial), CertificateDer: der})
	})
}

func (*Store) AuthorizedNames(sc transaction.Scope, account string, now time.Time) ([]string, error) {
	var out []string
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		out, e = q.CurrentAuthorizedNames(c, dbgen.CurrentAuthorizedNamesParams{AccountID: account, Expires: pgtype.Timestamptz{Time: now, Valid: true}})
		return e
	})
	return out, e
}

func (*Store) IssuerDER(sc transaction.Scope, id domain.IssuerID) ([]byte, error) {
	var out []byte
	e := use(sc, func(c context.Context, q *dbgen.Queries) error {
		var e error
		out, e = q.IssuerDER(c, string(id))
		return e
	})
	return out, e
}

func (*Store) AcceptRootCRL(sc transaction.Scope, v status.RootCRL) error {
	return use(sc, func(c context.Context, q *dbgen.Queries) error {
		n, e := q.AcceptRootCRL(c, dbgen.AcceptRootCRLParams{IssuerID: string(v.Issuer), Number: v.Number, Der: v.DER, RevokedSerials: v.RevokedSerials})
		if e == nil && n != 1 {
			return status.ErrDenied
		}
		return e
	})
}
