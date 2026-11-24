package acme

import (
	"context"
	"errors"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
	"time"
)

var (
	ErrNotFound    = errors.New("ACME account does not exist")
	ErrDenied      = errors.New("ACME authorization denied")
	ErrBadNonce    = errors.New("ACME nonce rejected")
	ErrConflict    = errors.New("ACME account key already exists")
	ErrEABRequired = errors.New("external account binding required")
)

type Repository interface {
	Account(transaction.Scope, string, string) (domain.Account, error)
	AccountByKey(transaction.Scope, string, string) (domain.Account, error)
	Principal(transaction.Scope, string) (domain.Principal, error)
	BindingPrincipal(transaction.Scope, string) (string, error)
	Binding(transaction.Scope, string) (domain.Binding, error)
	ConsumeBinding(transaction.Scope, string) error
	InsertAccount(transaction.Scope, domain.Account) error
	SaveAccount(transaction.Scope, domain.Account) error
	AddNonce(transaction.Scope, string, time.Time) error
	ConsumeNonce(transaction.Scope, string, time.Time) error
}
type Random interface {
	Random() (string, error)
	Digest(string) string
}
type Opener interface {
	Open(string, []byte) ([]byte, error)
}

// PublicKey contains only validated public material and a standard thumbprint.
type PublicKey struct {
	Encoded    []byte
	Thumbprint string
}

// Crypto is implemented by the standard JOSE adapter; no JOSE or crypto types
// cross into the application. Wire/header interpretation belongs to transport.
type Crypto interface {
	PublicKey([]byte) (PublicKey, error)
	Verify([]byte, []byte, bool) ([]byte, error)
}
type BindingProof interface {
	VerifyBinding(secret []byte, expected PublicKey) error
}
type Clock func() time.Time

func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}
