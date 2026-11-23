package statuscache

import (
	"context"
	"gatebeam/internal/modules/certificates/domain"
	"time"
)

type Request struct {
	DER               []byte
	IssuerFingerprint string
}
type Store interface {
	Load(context.Context, string) (domain.CachedStatus, error)
	Save(context.Context, string, domain.CachedStatus) error
	// Check persists a monotonic observation time and an irreversible local
	// revoked floor for a canonical issuer/serial key, before returning a result.
	Check(context.Context, string, time.Time, bool) (bool, error)
}
type Fetcher interface {
	Fetch(context.Context, string, []byte) ([]byte, error)
}

type Identity struct{ IssuerFingerprint, CertKey, CacheKey string }
type Verdict struct{ Good, Revoked bool }
type Verifier interface {
	Request(Request) (Identity, error)
	Verify(Request, []byte, time.Time) (Verdict, error)
	AddIssuers([][]byte) error
	Issuers() [][]byte
}
