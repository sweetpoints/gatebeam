package application

import (
	"context"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
)

// IssuerStore stores only public metadata. Signing remains in CA infrastructure.
type IssuerStore interface {
	Register(transaction.Scope, domain.Issuer, []byte) error
	ReserveSerial(transaction.Scope, domain.IssuerID, domain.Serial) error
}
type OfflineGenerator interface {
	Generate(context.Context, BootstrapCommand) error
}
