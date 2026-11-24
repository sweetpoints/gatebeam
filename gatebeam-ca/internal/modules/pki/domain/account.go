package domain

import "errors"

var ErrAccountDeactivated = errors.New("ACME account deactivated")

// Account persists a public key and principal binding, never a private key.
type Account struct {
	Revision                                       int64
	ID, PrincipalID, Directory, Thumbprint, Status string
	Key                                            []byte
	Contacts                                       []string
}

func (a *Account) ChangeKey(old, next string, key []byte) error {
	if a.Status != "valid" || a.Thumbprint != old || old == next || next == "" || len(key) == 0 {
		return ErrPolicy
	}
	a.Thumbprint = next
	a.Key = append([]byte(nil), key...)
	return nil
}
func (a *Account) Deactivate() error {
	if a.Status != "valid" {
		return ErrPolicy
	}
	a.Status = "deactivated"
	return nil
}
