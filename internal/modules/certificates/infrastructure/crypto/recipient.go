package crypto

import "gatebeam/internal/platform/secrets"

func (Crypto) SealRecipient(recipient, label string, plain []byte) ([]byte, error) {
	sealer, e := secrets.NewRecipient(recipient)
	if e != nil {
		return nil, e
	}
	return sealer.Seal(label, plain)
}
