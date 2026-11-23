package archive

import "gatebeam/internal/platform/transaction"

// LegacyAuthority binds the registered original owner under its registry lock.
// The log owner never reads or changes the deployment registry itself.
type LegacyAuthority interface {
	AuthorizeLegacyMappingWithin(transaction.Scope, string) error
}
