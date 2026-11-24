-- +goose Up
CREATE TABLE pki_eab_envelopes (
 id text PRIMARY KEY REFERENCES pki_eab(id),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 8192)
);
-- +goose Down
DROP TABLE pki_eab_envelopes;
