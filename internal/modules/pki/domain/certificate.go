package domain

import "time"

// IssuedCertificate is committed with its order before any DER is returned.
type IssuedCertificate struct {
	OrderID             string
	IssuerID            IssuerID
	Serial              Serial
	DER, Chain          []byte
	NotBefore, NotAfter time.Time
}
