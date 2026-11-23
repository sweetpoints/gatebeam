// Package preflight checks an explicitly selected old/new entry without changing
// business DNS, site policy, trust, client credentials or request headers.
package preflight

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	"gatebeam/internal/modules/deployment/domain"
	"net/netip"
	"strings"
	"time"
)

type EntryAddress struct {
	Role    string         `json:"role"`
	Mode    string         `json:"mode"`
	Address netip.AddrPort `json:"address"`
	Domain  string         `json:"domain,omitempty"`
	Path    string         `json:"path"`
}
type Report struct {
	SiteID   string       `json:"site_id"`
	Revision int64        `json:"revision"`
	Entry    EntryAddress `json:"entry"`
	Ready    bool         `json:"ready"`
	Result   string       `json:"result"`
	Reason   string       `json:"reason,omitempty"`
}
type Source interface {
	Site(context.Context, string) (app.Site, error)
}
type Service struct {
	source    Source
	probe     health.Prober
	protected []netip.Prefix
}

func New(s Source, p health.Prober, protected []netip.Prefix) *Service {
	// A development/test assembly without operator control-network inventory
	// cannot safely distinguish private entry addresses from private controls.
	if len(protected) == 0 {
		protected = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}
	}
	return &Service{s, p, append([]netip.Prefix(nil), protected...)}
}
func (s *Service) Check(ctx context.Context, siteID string, entry EntryAddress) (Report, error) {
	report := Report{SiteID: siteID, Entry: entry}
	ip := entry.Address.Addr().Unmap()
	if (entry.Role != "old" && entry.Role != "new") || (entry.Mode != "direct" && entry.Mode != "cloudflare") || !entry.Address.IsValid() || entry.Address.Port() == 0 || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" || ip == netip.MustParseAddr("fd00:ec2::254") || ip == netip.MustParseAddr("fd20:ce::254") || !strings.HasPrefix(entry.Path, "/") || strings.HasPrefix(entry.Path, "//") || strings.ContainsAny(entry.Path, "\r\n?#") || len(entry.Path) > 2048 {
		return report, domain.ErrInvalid
	}
	for _, p := range s.protected {
		if p.Contains(ip) {
			return report, domain.ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	site, e := s.source.Site(ctx, siteID)
	if e != nil {
		return report, e
	}
	report.Revision = site.Revision
	name := entry.Domain
	if name == "" && len(site.Config.Domains) > 0 {
		name = site.Config.Domains[0]
	}
	valid := false
	for _, domain := range site.Config.Domains {
		if domain == name {
			valid = true
		}
	}
	if !valid {
		return report, domain.ErrInvalid
	}
	report.Entry.Domain = name
	// Cloudflare's authenticated address/provider binding is not available before
	// its owner implementation. A supplied IP or label never proves a CF path.
	if entry.Mode == "cloudflare" {
		report.Result = "unavailable"
		report.Reason = "cloudflare_provider_unavailable"
		return report, nil
	}
	if site.Config.Cloudflare.Mode == "proxied" || site.Config.Cloudflare.RequireOriginPull || (site.Config.ClientVerification.Mode != "" && site.Config.ClientVerification.Mode != "off") {
		report.Result = "policy_refused"
		report.Reason = "cloudflare_aop_or_client_certificate_required"
		return report, nil
	}
	e = s.probe.Check(ctx, health.Probe{Address: entry.Address, Protocol: "https", HTTPHost: name, TLSName: name, Path: entry.Path})
	if e != nil {
		report.Result = "failed"
		report.Reason = "tls_or_http_probe_failed"
		return report, nil
	}
	report.Result = "passed"
	report.Ready = true
	return report, nil
}
