package domain

import "time"

// CachedStatus stores the original CA signature; it carries no signing key.
type CachedStatus struct {
	DER        []byte
	ObservedAt time.Time
}
