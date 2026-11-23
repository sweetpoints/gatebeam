// Package domain owns certificate policy and immutable material revision rules.
package domain

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid certificate resource")
	ErrConflict    = errors.New("certificate resource changed")
	ErrUnavailable = errors.New("certificate material unavailable")
	ErrDenied      = errors.New("certificate management denied")
	ErrNotFound    = errors.New("certificate resource not found")
)
var namePattern = regexp.MustCompile(`^(\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

type Spec struct {
	Names         []string `json:"names"`
	Purpose       string   `json:"purpose"`
	Method        string   `json:"method"`
	ProviderID    string   `json:"provider_id,omitempty"`
	Challenge     string   `json:"challenge,omitempty"`
	CredentialIDs []string `json:"credential_ids,omitempty"`
	TrustRevision int64    `json:"trust_revision,omitempty"`
	TrustID       string   `json:"trust_id,omitempty"`
}

func (s Spec) Validate() error {
	if (s.TrustID == "" && s.TrustRevision != 0) || (s.TrustID != "" && s.TrustRevision < 1) {
		return ErrInvalid
	}
	if len(s.Names) < 1 || len(s.Names) > 100 || (s.Purpose != "serverAuth" && s.Purpose != "clientAuth") {
		return ErrInvalid
	}
	names := map[string]bool{}
	for _, n := range s.Names {
		if len(n) > 253 || !namePattern.MatchString(n) || strings.Contains(n, "..") || names[n] {
			return ErrInvalid
		}
		names[n] = true
		for _, label := range strings.Split(strings.TrimPrefix(n, "*."), ".") {
			if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return ErrInvalid
			}
		}
	}
	switch s.Method {
	case "import":
		if s.ProviderID != "" || s.Challenge != "" || len(s.CredentialIDs) > 0 {
			return ErrInvalid
		}
	case "acme":
		if s.ProviderID == "" || (s.Challenge != "http-01" && s.Challenge != "dns-01") {
			return ErrInvalid
		}
		if (s.Challenge == "dns-01" && (len(s.CredentialIDs) == 0 || len(s.CredentialIDs) > 20)) || (s.Challenge == "http-01" && len(s.CredentialIDs) > 0) {
			return ErrInvalid
		}
		for _, n := range s.Names {
			if strings.HasPrefix(n, "*.") && s.Challenge != "dns-01" {
				return ErrInvalid
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (s Spec) Automatic() bool { return s.Method == "acme" }
func (s Spec) Compatible(n Spec) bool {
	a, b := slices.Clone(s.Names), slices.Clone(n.Names)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b) && s.Purpose == n.Purpose && s.TrustID == n.TrustID && s.TrustRevision == n.TrustRevision && s.Method == n.Method && s.ProviderID == n.ProviderID
}

type ProviderAccount struct {
	Provider string `json:"provider"`
	Email    string `json:"email"`
	EABKeyID string `json:"eab_key_id,omitempty"`
}

func (p ProviderAccount) Validate() error {
	if p.Provider != "letsencrypt" && p.Provider != "zerossl" && p.Provider != "google" && p.Provider != "internal-client" && p.Provider != "internal-server" {
		return ErrInvalid
	}
	if len(p.Email) > 254 || !strings.Contains(p.Email, "@") || strings.ContainsAny(p.Email, "\r\n\x00") {
		return ErrInvalid
	}
	if p.Provider != "letsencrypt" && p.EABKeyID == "" {
		return ErrInvalid
	}
	return nil
}

type DNSCredential struct {
	ZoneID   string `json:"zone_id"`
	ZoneName string `json:"zone_name"`
}

func (c DNSCredential) Validate() error {
	if len(c.ZoneID) != 32 || strings.Trim(c.ZoneID, "0123456789abcdef") != "" || !namePattern.MatchString(c.ZoneName) || strings.Contains(c.ZoneName, "*") {
		return ErrInvalid
	}
	return nil
}

type TrustBundle struct {
	Purpose              string   `json:"purpose"`
	Fingerprints         []string `json:"fingerprints"`
	StatusProfile        string   `json:"status_profile,omitempty"`
	OriginPullAuthorized bool     `json:"origin_pull_authorized"`
}

func (t TrustBundle) Validate() error {
	if (t.Purpose != "serverAuth" && t.Purpose != "clientAuth") || len(t.Fingerprints) == 0 || len(t.Fingerprints) > 20 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, f := range t.Fingerprints {
		if len(f) != 64 || strings.Trim(f, "0123456789abcdef") != "" || seen[f] {
			return ErrInvalid
		}
		seen[f] = true
	}
	return nil
}

// Accepts binds usage to the standard directory chosen by this account. Internal
// identities require explicit trust; a public CA is never a client-identity fallback.
func (p ProviderAccount) Accepts(s Spec) bool {
	if p.Validate() != nil || s.Validate() != nil {
		return false
	}
	switch p.Provider {
	case "internal-client":
		return s.Purpose == "clientAuth" && s.TrustID != ""
	case "internal-server":
		return s.Purpose == "serverAuth" && s.TrustID != ""
	default:
		return s.Purpose == "serverAuth"
	}
}
