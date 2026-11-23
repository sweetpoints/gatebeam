package postgres

import (
	"context"
	"encoding/json"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/domain"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
)

type Distribution struct{}

func NewDistribution() *Distribution { return &Distribution{} }
func (*Distribution) VersionWithin(sc transaction.Scope, id string) (out app.StoredVersion, err error) {
	if err = NewMaterialReader().ReadLock(sc); err != nil {
		return out, err
	}
	err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		var body []byte
		e := tx.QueryRow(ctx, `SELECT v.body,v.certificate_pem,v.encrypted_key FROM certificates_versions v JOIN certificates_attempts a ON a.current_version=v.id JOIN certificates_resources r ON r.kind='spec' AND r.id=v.spec_id WHERE v.id=$1 AND r.enabled`, id).Scan(&body, &out.CertificatePEM, &out.EncryptedKey)
		if e == pgx.ErrNoRows {
			return domain.ErrUnavailable
		}
		if e != nil {
			return e
		}
		return json.Unmarshal(body, &out.Version)
	})
	return
}
func (*Distribution) EnvelopeWithin(sc transaction.Scope, b app.RecipientBinding) (out []byte, err error) {
	err = pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT ciphertext FROM certificates_node_envelopes WHERE version_id=$1 AND node_id=$2 AND node_epoch=$3 AND recipient=$4`, b.VersionID, b.Node.ID, int64(b.Node.Epoch), b.Recipient).Scan(&out)
		if e == pgx.ErrNoRows {
			return domain.ErrUnavailable
		}
		return e
	})
	return
}
func (*Distribution) SaveEnvelopeWithin(sc transaction.Scope, b app.RecipientBinding, ciphertext []byte) error {
	return pg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO certificates_node_envelopes(version_id,node_id,node_epoch,recipient,ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, b.VersionID, b.Node.ID, int64(b.Node.Epoch), b.Recipient, ciphertext)
		return e
	})
}
