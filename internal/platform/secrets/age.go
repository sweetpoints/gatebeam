// Package secrets encrypts labelled secret payloads using the standard age format.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"io"
	"os"
)

const maxPayload = 1 << 20

var errSecret = errors.New("secret operation failed")

type Store struct {
	identity   *age.X25519Identity
	recipients []age.Recipient
}
type payload struct {
	Version int    `json:"version"`
	Label   string `json:"label"`
	Plain   []byte `json:"plain"`
}

// New loads one X25519 age identity. Identity data is never included in errors.
func New(identityFile string) (*Store, error) {
	f, err := os.Open(identityFile)
	if err != nil {
		return nil, errSecret
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return nil, errSecret
	}
	keys, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil || len(keys) != 1 {
		return nil, errSecret
	}
	key, ok := keys[0].(*age.X25519Identity)
	if !ok {
		return nil, errSecret
	}
	return &Store{identity: key}, nil
}
func (s *Store) Seal(label string, plain []byte) ([]byte, error) {
	if s == nil || s.identity == nil || label == "" || len(label) > 1024 || len(plain) > maxPayload {
		return nil, errSecret
	}
	body, err := json.Marshal(payload{1, label, plain})
	if err != nil {
		return nil, errSecret
	}
	defer clear(body)
	recipients := s.recipients
	if len(recipients) == 0 {
		recipients = []age.Recipient{s.identity.Recipient()}
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipients...)
	if err != nil {
		return nil, errSecret
	}
	if _, err = w.Write(body); err != nil {
		return nil, errSecret
	}
	if err = w.Close(); err != nil {
		return nil, errSecret
	}
	return out.Bytes(), nil
}
func (s *Store) Open(label string, cipher []byte) ([]byte, error) {
	if s == nil || s.identity == nil || label == "" || len(cipher) > 2*maxPayload {
		return nil, errSecret
	}
	r, err := age.Decrypt(bytes.NewReader(cipher), s.identity)
	if err != nil {
		return nil, errSecret
	}
	body, err := io.ReadAll(io.LimitReader(r, 2*maxPayload+1))
	if err != nil || len(body) > 2*maxPayload {
		return nil, errSecret
	}
	var p payload
	if json.Unmarshal(body, &p) != nil || p.Version != 1 || p.Label != label || len(p.Plain) > maxPayload {
		return nil, errSecret
	}
	return p.Plain, nil
}

// NewRoleStore loads an independent private identity and seals new payloads to
// the operator-authorized role recipients using standard age recipient stanzas.
// Existing single-recipient ciphertext still requires its original holder.
func NewRoleStore(identityFile string, recipients []string) (*Store, error) {
	store, err := New(identityFile)
	if err != nil {
		return nil, err
	}
	parsed, err := parseRecipients(recipients)
	if err != nil {
		return nil, err
	}
	own := store.identity.Recipient().String()
	included := false
	for _, recipient := range parsed {
		if recipient.String() == own {
			included = true
		}
	}
	if !included {
		return nil, errSecret
	}
	for _, recipient := range parsed {
		store.recipients = append(store.recipients, recipient)
	}
	return store, nil
}
