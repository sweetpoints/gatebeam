-- +goose Up
-- PKI-owned public issuer metadata and collision reservations. No signing key is
-- stored here. PKI management receives SELECT only; CA alone writes these tables.
CREATE TABLE pki_issuers (
 id text PRIMARY KEY CHECK (id <> ''),
 fingerprint text NOT NULL UNIQUE CHECK (fingerprint <> ''),
 certificate_der bytea NOT NULL CHECK (octet_length(certificate_der) BETWEEN 1 AND 65536),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL CHECK (not_after > not_before),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE pki_serial_reservations (
 issuer_id text NOT NULL REFERENCES pki_issuers(id),
 serial text NOT NULL CHECK (serial ~ '^[0-7][0-9a-f]{39}$' AND serial <> repeat('0',40)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (issuer_id,serial)
);
-- +goose Down
DROP TABLE pki_serial_reservations,pki_issuers;
