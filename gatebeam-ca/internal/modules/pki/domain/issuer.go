// Package domain owns PKI policy values without cryptographic or I/O capabilities.
package domain

import "time"

type IssuerID string
type Serial string
type Usage string

const (
	ServerAuth Usage = "serverAuth"
	ClientAuth Usage = "clientAuth"
)

// Issuer contains public metadata only. Private material never enters the domain.
type Issuer struct {
	ID          IssuerID
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
}
