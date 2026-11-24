package secrets

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
)

// RecipientStore can only encrypt to the CA's public recipient. API assembly
// never needs the CA identity or a decryption capability for EAB credentials.
type RecipientStore struct {
	recipient  *age.X25519Recipient
	recipients []age.Recipient
}

func NewRecipient(public string) (*RecipientStore, error) { return NewRecipients([]string{public}) }
func parseRecipients(public []string) ([]*age.X25519Recipient, error) {
	if len(public) == 0 || len(public) > 32 {
		return nil, errSecret
	}
	var out []*age.X25519Recipient
	seen := map[string]bool{}
	for _, value := range public {
		recipient, err := age.ParseX25519Recipient(value)
		if err != nil {
			return nil, errSecret
		}
		if !seen[recipient.String()] {
			out = append(out, recipient)
			seen[recipient.String()] = true
		}
	}
	return out, nil
}

// NewRecipients has no decryption capability, even for shared-role payloads.
func NewRecipients(public []string) (*RecipientStore, error) {
	recipients, err := parseRecipients(public)
	if err != nil {
		return nil, err
	}
	store := &RecipientStore{recipient: recipients[0]}
	for _, recipient := range recipients {
		store.recipients = append(store.recipients, recipient)
	}
	return store, nil
}
func (s *RecipientStore) Recipient() string { return s.recipient.String() }
func (s *Store) Recipient() string          { return s.identity.Recipient().String() }
func (s *RecipientStore) Seal(label string, plain []byte) ([]byte, error) {
	if s == nil || s.recipient == nil || label == "" || len(label) > 1024 || len(plain) > maxPayload {
		return nil, errSecret
	}
	body, e := json.Marshal(payload{1, label, plain})
	if e != nil {
		return nil, errSecret
	}
	defer clear(body)
	var out bytes.Buffer
	w, e := age.Encrypt(&out, s.recipients...)
	if e != nil {
		return nil, errSecret
	}
	if _, e = w.Write(body); e != nil {
		return nil, errSecret
	}
	if e = w.Close(); e != nil {
		return nil, errSecret
	}
	return out.Bytes(), nil
}
