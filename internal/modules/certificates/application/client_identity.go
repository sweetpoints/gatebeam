package application

import (
	"encoding/json"
	"gatebeam/internal/modules/certificates/domain"
)

// ValidateEnrollment binds the certificate specification to the account's fixed
// standard directory policy. It grants no signing capability and carries no
// protocol profile, HTTP header, or alternate CSR channel.
func ValidateEnrollment(spec Spec, record Record) error {
	var account ProviderAccount
	if json.Unmarshal(record.Body, &account) != nil || !account.Accepts(spec) {
		return domain.ErrInvalid
	}
	return nil
}
