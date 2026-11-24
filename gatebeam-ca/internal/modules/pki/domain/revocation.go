package domain

import (
	"errors"
	"time"
)

var (
	ErrAlreadyRevoked   = errors.New("certificate already revoked")
	ErrRevocationReason = errors.New("unsupported revocation reason")
)

type CertificateStatus string

const (
	StatusGood    CertificateStatus = "good"
	StatusRevoked CertificateStatus = "revoked"
	StatusUnknown CertificateStatus = "unknown"
)

type Revocation struct {
	Serial Serial
	Reason int
	At     time.Time
}

// Leaf revocations are permanent. Hold/removeFromCRL and CA-only reasons are
// deliberately unsupported; an ACME client receives badRevocationReason.
func NewRevocation(serial Serial, reason int, now time.Time) (Revocation, error) {
	switch reason {
	case 0, 1, 3, 4, 5, 9:
	default:
		return Revocation{}, ErrRevocationReason
	}
	if now.IsZero() || len(serial) != 40 {
		return Revocation{}, ErrPolicy
	}
	for _, c := range serial {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return Revocation{}, ErrPolicy
		}
	}
	if serial[0] > '7' || serial == Serial("0000000000000000000000000000000000000000") {
		return Revocation{}, ErrPolicy
	}
	return Revocation{serial, reason, now}, nil
}
func (r Revocation) Revoke(int, time.Time) error { return ErrAlreadyRevoked }
