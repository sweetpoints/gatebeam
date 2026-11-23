// Package domain owns ingress configuration rules independently of transport and storage.
package domain

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid ingress configuration")
	ErrConflict    = errors.New("ingress revision conflict")
	ErrNotFound    = errors.New("ingress resource not found")
	ErrReferenced  = errors.New("ingress resource is referenced")
	ErrUnavailable = errors.New("TLS materials unavailable until certificate integration")
)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidID(s string) bool { return uuid.MatchString(s) }
func Host(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return "", ErrInvalid
	}
	for _, v := range strings.Split(s, ".") {
		if !label.MatchString(v) {
			return "", ErrInvalid
		}
	}
	return s, nil
}
func Name(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > 128 || strings.ContainsAny(s, "\x00\r\n") {
		return "", ErrInvalid
	}
	return s, nil
}
func IDs(ids []string) ([]string, error) {
	out := append([]string{}, ids...)
	sort.Strings(out)
	for i, id := range out {
		if !ValidID(id) || (i > 0 && id == out[i-1]) {
			return nil, ErrInvalid
		}
	}
	return out, nil
}

type TargetRef struct {
	ID string `json:"id,omitempty"`
}

func (r TargetRef) Validate() error {
	if r.ID == "" {
		return nil
	}
	if !ValidID(r.ID) {
		return ErrInvalid
	}
	return nil
}

type MaterialRef struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Status   string `json:"status"`
}

func (r MaterialRef) Validate() error {
	if !ValidID(r.ID) || r.Revision < 1 || r.Status != "unavailable" {
		return ErrInvalid
	}
	return nil
}

type Route struct {
	Rate        *RatePolicy `json:"rate,omitempty"`
	Match       string      `json:"match"`
	Path        string      `json:"path"`
	StripPrefix bool        `json:"strip_prefix"`
	Target      TargetRef   `json:"target"`
}
type MaintenancePolicy struct {
	Enabled bool   `json:"enabled"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}
type CFPolicy struct {
	Mode                 string   `json:"mode"`
	TrustedProxyNetworks []string `json:"trusted_proxy_networks"`
	RequireOriginPull    bool     `json:"require_origin_pull"`
}
type ClientVerification struct {
	Mode       string       `json:"mode"`
	Trust      *MaterialRef `json:"trust,omitempty"`
	Depth      int          `json:"depth"`
	Revocation string       `json:"revocation"`
}
type AccessPolicy struct {
	Allow     []string `json:"allow"`
	Deny      []string `json:"deny"`
	DenyPaths []string `json:"deny_paths"`
}
type RatePolicy struct {
	RequestsPerSecond int `json:"requests_per_second"`
	Burst             int `json:"burst"`
	Connections       int `json:"connections"`
	Status            int `json:"status"`
}
type ConnectionPolicy struct {
	ConnectTimeoutSeconds int   `json:"connect_timeout_seconds"`
	ReadTimeoutSeconds    int   `json:"read_timeout_seconds"`
	SendTimeoutSeconds    int   `json:"send_timeout_seconds"`
	MaxBodyBytes          int64 `json:"max_body_bytes"`
	WebSocket             bool  `json:"websocket"`
	SSE                   bool  `json:"sse"`
	BufferResponses       bool  `json:"buffer_responses"`
}
type SiteConfig struct {
	Enabled            bool               `json:"enabled"`
	Domains            []string           `json:"domains"`
	DefaultTarget      TargetRef          `json:"default_target"`
	Routes             []Route            `json:"routes"`
	Maintenance        MaintenancePolicy  `json:"maintenance"`
	Cloudflare         CFPolicy           `json:"cloudflare"`
	EntryCertificate   *MaterialRef       `json:"entry_certificate,omitempty"`
	ClientVerification ClientVerification `json:"client_verification"`
	Access             AccessPolicy       `json:"access"`
	Rate               RatePolicy         `json:"rate"`
	Connection         ConnectionPolicy   `json:"connection"`
}
type Site struct {
	Deleted           bool        `json:"deleted,omitempty"`
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	GroupIDs          []string    `json:"group_ids"`
	Revision          int64       `json:"revision"`
	Draft             SiteConfig  `json:"draft"`
	PublishedRevision int64       `json:"published_revision"`
	Published         *SiteConfig `json:"published,omitempty"`
}

func (c *SiteConfig) Normalize() error {
	*c = c.Clone()
	if len(c.Domains) == 0 || len(c.Domains) > 100 || len(c.Routes) > 500 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for i, v := range c.Domains {
		h, e := Host(v)
		if e != nil || seen[h] {
			return ErrInvalid
		}
		seen[h] = true
		c.Domains[i] = h
	}
	sort.Strings(c.Domains)
	if e := c.DefaultTarget.Validate(); e != nil {
		return e
	}
	seen = map[string]bool{}
	for _, r := range c.Routes {
		if (r.Match != "exact" && r.Match != "prefix") || !ValidPath(r.Path) || (r.StripPrefix && r.Match != "prefix") || r.Target.ID == "" || r.Target.Validate() != nil || seen[r.Match+":"+r.Path] {
			return ErrInvalid
		}
		if r.Rate != nil {
			if e := r.Rate.Normalize(); e != nil {
				return e
			}
		}
		seen[r.Match+":"+r.Path] = true
	}
	if c.Maintenance.Status == 0 {
		c.Maintenance.Status = 503
	}
	if c.Maintenance.Status < 400 || c.Maintenance.Status > 599 || len(c.Maintenance.Message) > 1024 {
		return ErrInvalid
	}
	if c.Cloudflare.Mode == "" {
		c.Cloudflare.Mode = "off"
	}
	if c.Cloudflare.Mode != "off" && c.Cloudflare.Mode != "proxied" {
		return ErrInvalid
	}
	if c.Cloudflare.Mode == "off" && (len(c.Cloudflare.TrustedProxyNetworks) > 0 || c.Cloudflare.RequireOriginPull) {
		return ErrInvalid
	}
	if c.ClientVerification.Mode == "" {
		c.ClientVerification.Mode = "off"
	}
	v := c.ClientVerification
	if v.Mode != "off" && v.Mode != "optional" && v.Mode != "required" {
		return ErrInvalid
	}
	if v.Mode == "off" && (v.Trust != nil || v.Depth != 0 || v.Revocation != "") {
		return ErrInvalid
	}
	if v.Mode != "off" && (v.Trust == nil || v.Trust.Validate() != nil || v.Depth < 1 || v.Depth > 10 || (v.Revocation != "crl" && v.Revocation != "ocsp" && v.Revocation != "crl_ocsp")) {
		return ErrInvalid
	}
	if c.EntryCertificate != nil && c.EntryCertificate.Validate() != nil {
		return ErrInvalid
	}
	for _, p := range c.Access.DenyPaths {
		if !ValidPath(p) {
			return ErrInvalid
		}
	}
	r := c.Rate
	if r.RequestsPerSecond < 0 || r.RequestsPerSecond > 1000000 || r.Burst < 0 || r.Burst > 1000000 || r.Connections < 0 || r.Connections > 1000000 {
		return ErrInvalid
	}
	if c.Rate.Status == 0 {
		c.Rate.Status = 429
	}
	if c.Rate.Status != 429 && c.Rate.Status != 503 {
		return ErrInvalid
	}
	p := &c.Connection
	if p.ConnectTimeoutSeconds == 0 {
		p.ConnectTimeoutSeconds = 5
	}
	if p.ReadTimeoutSeconds == 0 {
		p.ReadTimeoutSeconds = 60
	}
	if p.SendTimeoutSeconds == 0 {
		p.SendTimeoutSeconds = 60
	}
	if p.MaxBodyBytes == 0 {
		p.MaxBodyBytes = 10485760
	}
	if p.ConnectTimeoutSeconds < 1 || p.ConnectTimeoutSeconds > 300 || p.ReadTimeoutSeconds < 1 || p.ReadTimeoutSeconds > 3600 || p.SendTimeoutSeconds < 1 || p.SendTimeoutSeconds > 3600 || p.MaxBodyBytes < 1 || p.MaxBodyBytes > 1<<40 {
		return ErrInvalid
	}
	return nil
}
func ValidPath(s string) bool {
	return len(s) > 0 && len(s) <= 2048 && s[0] == '/' && !strings.ContainsAny(s, "\x00\r\n?#\\")
}

// MatchRoute preserves method, body and query semantics: it selects only the route.
func (c SiteConfig) MatchRoute(path string) *Route {
	var best *Route
	for _, r := range c.Routes {
		r := r
		if r.Rate != nil {
			rate := *r.Rate
			r.Rate = &rate
		}
		if r.Match == "exact" && path == r.Path {
			return &r
		}
		if r.Match == "prefix" && strings.HasPrefix(path, r.Path) && (best == nil || len(r.Path) > len(best.Path)) {
			best = &r
		}
	}
	return best
}
func (c SiteConfig) TargetRefs() []TargetRef {
	out := []TargetRef{}
	if c.DefaultTarget.ID != "" {
		out = append(out, c.DefaultTarget)
	}
	for _, r := range c.Routes {
		out = append(out, r.Target)
	}
	return out
}
func (c SiteConfig) Materials() []MaterialRef {
	out := []MaterialRef{}
	if c.EntryCertificate != nil {
		out = append(out, *c.EntryCertificate)
	}
	if c.ClientVerification.Trust != nil {
		out = append(out, *c.ClientVerification.Trust)
	}
	return out
}
func (c SiteConfig) Ready() error {
	if c.EntryCertificate != nil || c.ClientVerification.Trust != nil || c.Cloudflare.RequireOriginPull {
		return ErrUnavailable
	}
	return nil
}

// ReviseDraft advances only the configuration draft. Published content is owned
// by an explicit release and is never updated as a side effect of editing.
func (s *Site) ReviseDraft(c SiteConfig, expected int64) error {
	c = c.Clone()
	if s.Deleted {
		return ErrNotFound
	}
	if expected < 1 || s.Revision != expected {
		return ErrConflict
	}
	if e := c.Normalize(); e != nil {
		return e
	}
	s.Draft = c
	s.Revision++
	return nil
}
func (s *Site) MoveTo(groups []string, expected int64) error {
	if s.Deleted {
		return ErrNotFound
	}
	if expected < 1 || s.Revision != expected {
		return ErrConflict
	}
	if len(groups) > 100 {
		return ErrInvalid
	}
	ids, e := IDs(groups)
	if e != nil {
		return e
	}
	s.GroupIDs = ids
	s.Revision++
	return nil
}

// Remove retains a registered identity for current-scope history and retries.
// Removing a published site would implicitly change live traffic and is denied.
func (s *Site) Remove(expected int64) error {
	if s.Deleted {
		return ErrNotFound
	}
	if expected < 1 || s.Revision != expected {
		return ErrConflict
	}
	if s.Published != nil || s.PublishedRevision != 0 {
		return ErrReferenced
	}
	s.Deleted = true
	return nil
}

func copyMaterial(p *MaterialRef) *MaterialRef {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func (c SiteConfig) Clone() SiteConfig {
	c.Domains = append([]string{}, c.Domains...)
	c.Routes = append([]Route{}, c.Routes...)
	for i := range c.Routes {
		if c.Routes[i].Rate != nil {
			r := *c.Routes[i].Rate
			c.Routes[i].Rate = &r
		}
	}
	c.EntryCertificate = copyMaterial(c.EntryCertificate)
	c.ClientVerification.Trust = copyMaterial(c.ClientVerification.Trust)
	c.Access.Allow = append([]string{}, c.Access.Allow...)
	c.Access.Deny = append([]string{}, c.Access.Deny...)
	c.Access.DenyPaths = append([]string{}, c.Access.DenyPaths...)
	c.Cloudflare.TrustedProxyNetworks = append([]string{}, c.Cloudflare.TrustedProxyNetworks...)
	return c
}

func (r *RatePolicy) Normalize() error {
	if r.RequestsPerSecond < 0 || r.RequestsPerSecond > 1000000 || r.Burst < 0 || r.Burst > 1000000 || r.Connections < 0 || r.Connections > 1000000 {
		return ErrInvalid
	}
	if r.Status == 0 {
		r.Status = 429
	}
	if r.Status != 429 && r.Status != 503 {
		return ErrInvalid
	}
	return nil
}
