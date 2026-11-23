package domain

import (
	"net/netip"
	"strings"
)

type TargetMember struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	TLSName string `json:"tls_name"`
}
type HealthPolicy struct {
	Enabled            bool   `json:"enabled"`
	HTTPHost           string `json:"http_host"`
	Path               string `json:"path"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
}
type TargetConfig struct {
	Name              string         `json:"name"`
	Protocol          string         `json:"protocol"`
	Members           []TargetMember `json:"members"`
	HTTPHost          string         `json:"http_host"`
	TLSServerNameMode string         `json:"tls_server_name_mode,omitempty"`
	TLSNameMode       string         `json:"tls_name_mode"`
	TLSName           string         `json:"tls_name"`
	Trust             *MaterialRef   `json:"trust,omitempty"`
	ClientCertificate *MaterialRef   `json:"client_certificate,omitempty"`
	AllowedNetworks   []string       `json:"allowed_networks"`
	Health            HealthPolicy   `json:"health"`
}
type TargetGroup struct {
	ID                string        `json:"id"`
	Revision          int64         `json:"revision"`
	Config            TargetConfig  `json:"config"`
	PublishedRevision int64         `json:"published_revision"`
	Published         *TargetConfig `json:"published,omitempty"`
}

func (t *TargetConfig) Normalize() error {
	*t = t.Clone()
	n, e := Name(t.Name)
	if e != nil {
		return e
	}
	t.Name = n
	if t.Protocol != "http" && t.Protocol != "https" {
		return ErrInvalid
	}
	if len(t.Members) == 0 || len(t.Members) > 100 || len(t.AllowedNetworks) == 0 || len(t.AllowedNetworks) > 100 {
		return ErrInvalid
	}
	if t.HTTPHost != "" {
		t.HTTPHost, e = Host(t.HTTPHost)
		if e != nil {
			return e
		}
	}
	seen := map[string]map[int]bool{}
	for i, m := range t.Members {
		m.Address, e = ConnectionAddress(m.Address)
		if e != nil || m.Port < 1 || m.Port > 65535 || m.Weight < 1 || m.Weight > 1000 {
			return ErrInvalid
		}
		if seen[m.Address] == nil {
			seen[m.Address] = map[int]bool{}
		}
		if seen[m.Address][m.Port] {
			return ErrInvalid
		}
		seen[m.Address][m.Port] = true
		if m.TLSName != "" {
			m.TLSName, e = Host(m.TLSName)
			if e != nil {
				return e
			}
		}
		t.Members[i] = m
	}
	if t.Protocol == "http" {
		if t.Trust != nil || t.ClientCertificate != nil || t.TLSNameMode != "" || t.TLSServerNameMode != "" || t.TLSName != "" {
			return ErrInvalid
		}
		for _, m := range t.Members {
			if m.TLSName != "" {
				return ErrInvalid
			}
		}
	} else {
		if t.Trust == nil || t.Trust.Validate() != nil || (t.ClientCertificate != nil && t.ClientCertificate.Validate() != nil) {
			return ErrInvalid
		}
		if (t.TLSServerNameMode != "" && t.TLSServerNameMode != "send" && t.TLSServerNameMode != "verify_only") || (t.TLSServerNameMode == "verify_only" && t.ClientCertificate == nil) {
			return ErrInvalid
		}
		if t.TLSNameMode != "fixed" && t.TLSNameMode != "member" {
			return ErrInvalid
		}
		if t.TLSNameMode == "fixed" {
			t.TLSName, e = Host(t.TLSName)
			if e != nil {
				return e
			}
			for _, m := range t.Members {
				if m.TLSName != "" {
					return ErrInvalid
				}
			}
		} else {
			if t.TLSName != "" {
				return ErrInvalid
			}
			for i, m := range t.Members {
				if m.TLSName == "" {
					t.Members[i].TLSName = m.Address
				}
			}
		}
	}
	h := &t.Health
	if h.HTTPHost != "" {
		h.HTTPHost, e = Host(h.HTTPHost)
		if e != nil {
			return e
		}
	}
	if h.Path == "" {
		h.Path = "/"
	}
	if !ValidPath(h.Path) {
		return ErrInvalid
	}
	if h.IntervalSeconds == 0 {
		h.IntervalSeconds = 5
	}
	if h.TimeoutSeconds == 0 {
		h.TimeoutSeconds = 2
	}
	if h.HealthyThreshold == 0 {
		h.HealthyThreshold = 2
	}
	if h.UnhealthyThreshold == 0 {
		h.UnhealthyThreshold = 3
	}
	if h.IntervalSeconds < 1 || h.IntervalSeconds > 3600 || h.TimeoutSeconds < 1 || h.TimeoutSeconds > 60 || h.TimeoutSeconds > h.IntervalSeconds || h.HealthyThreshold < 1 || h.HealthyThreshold > 100 || h.UnhealthyThreshold < 1 || h.UnhealthyThreshold > 100 {
		return ErrInvalid
	}
	return nil
}
func (t TargetConfig) Materials() []MaterialRef {
	out := []MaterialRef{}
	if t.Trust != nil {
		out = append(out, *t.Trust)
	}
	if t.ClientCertificate != nil {
		out = append(out, *t.ClientCertificate)
	}
	return out
}
func (t TargetConfig) Ready() error {
	if t.Protocol == "https" || len(t.Materials()) > 0 {
		return ErrUnavailable
	}
	return nil
}

func (t *TargetGroup) Revise(c TargetConfig, expected int64) error {
	c = c.Clone()
	if !ValidID(t.ID) {
		return ErrInvalid
	}
	if expected < 0 || t.Revision != expected {
		return ErrConflict
	}
	if e := c.Normalize(); e != nil {
		return e
	}
	t.Config = c
	t.Revision++
	return nil
}

func (c TargetConfig) Clone() TargetConfig {
	c.Members = append([]TargetMember{}, c.Members...)
	c.AllowedNetworks = append([]string{}, c.AllowedNetworks...)
	c.Trust = copyMaterial(c.Trust)
	c.ClientCertificate = copyMaterial(c.ClientCertificate)
	return c
}

// ConnectionAddress parses literal addresses without DNS or network I/O. Names
// still use Host rules; HTTP Host and TLS identity have independent fields.
func ConnectionAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if ip, e := netip.ParseAddr(raw); e == nil {
		if ip.Zone() != "" {
			return "", ErrInvalid
		}
		return ip.Unmap().String(), nil
	}
	return Host(raw)
}
