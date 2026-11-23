package auth

import (
	identityapp "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Repository interface {
	Lock(transaction.Scope) error
	Empty(transaction.Scope) (bool, error)
	AccountByName(transaction.Scope, string) (domain.Account, error)
	AccountByID(transaction.Scope, string) (domain.Account, error)
	AccountByInvite(transaction.Scope, string) (domain.Account, error)
	SaveAccount(transaction.Scope, domain.Account) error
	CreateAccount(transaction.Scope, domain.Account) error
	SaveChallenge(transaction.Scope, domain.Challenge) error
	Challenge(transaction.Scope, string) (domain.Challenge, error)
	CreateSession(transaction.Scope, domain.Session) error
	Session(transaction.Scope, string) (domain.Session, error)
	RevokeSession(transaction.Scope, string) error
	ReplaceRecovery(transaction.Scope, string, []string) error
	ConsumeRecovery(transaction.Scope, string, string) (bool, error)
}
type Password interface {
	Hash(string) (string, error)
	Verify(string, string) (bool, bool)
}
type TOTP interface {
	Generate(string) (seed, uri string, err error)
	Verify(seed, code string, now time.Time) (int64, error)
}
type SecretStore interface {
	Seal(string, []byte) ([]byte, error)
	Open(string, []byte) ([]byte, error)
}
type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type Clock func() time.Time

// Actor is produced only by authenticated sessions; downstream authorization must
// revalidate the credential reference and current account version inside its transaction.
type Actor = identityapp.Actor
type LoginChallenge struct {
	ChallengeID string    `json:"challenge_id"`
	Expires     time.Time `json:"expires"`
}
type EnrollmentChallenge struct {
	InviteID        string    `json:"invite_id"`
	ProvisioningURI string    `json:"provisioning_uri"`
	Expires         time.Time `json:"expires"`
}
type EnrollmentResult struct {
	RecoveryCodes []string `json:"recovery_codes"`
}
type Session struct {
	Token     string    `json:"-"`
	CSRFToken string    `json:"csrf_token"`
	Expires   time.Time `json:"expires"`
	Actor     Actor     `json:"actor"`
}

type Credentials interface {
	// NewID generates a public resource UUIDv4, independently of opaque secret bearers.
	NewID() (string, error)
	Random() (string, error)
	Digest(string) string
	Equal(string, string) bool
}
