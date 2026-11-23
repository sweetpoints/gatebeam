// Package nginx compiles immutable deployment DTOs with fixed native directives.
// It performs no DNS, filesystem or process I/O and never consumes raw snippets.
package nginx

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	constrained "gatebeam/internal/modules/deployment/infrastructure/dns"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalid = errors.New("invalid or unavailable ingress runtime input")
var dnsName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var safePath = regexp.MustCompile(`^/[a-zA-Z0-9/_~.%-]*$`)
var version = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

type Compiler struct{}
type target struct {
	name                              string
	config                            app.TargetConfig
	endpoints                         map[string]string
	weights                           map[string]int
	live                              bool
	trust, crl, clientCert, clientKey string
}
type builder struct {
	files   map[string][]byte
	runtime edge.RuntimeState
	n       int
}

func validName(s string) bool {
	if !dnsName.MatchString(s) || strings.Contains(s, "..") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
	}
	return true
}
func token(s string) string { h := sha256.Sum256([]byte(s)); return "g" + hex.EncodeToString(h[:8]) }
func (b *builder) material(ref *app.MaterialRef, kind string, names []string) (string, string, error) {
	if ref == nil {
		return "", "", ErrInvalid
	}
	m, ok := b.runtime.Materials[ref.ID]
	if !ok || m.Revision != ref.Revision {
		return "", "", ErrInvalid
	}
	base := "materials/" + token(ref.ID+"/"+strconv.FormatInt(ref.Revision, 10)+"/"+kind)
	var data []byte
	if kind == "trust" {
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(m.TrustPEM) {
			return "", "", ErrInvalid
		}
		data = m.TrustPEM
	} else {
		pair, e := tls.X509KeyPair(m.CertificatePEM, m.KeyPEM)
		if e != nil || len(pair.Certificate) == 0 {
			return "", "", ErrInvalid
		}
		cert, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil || b.runtime.Now.IsZero() || b.runtime.Now.Before(cert.NotBefore) || !b.runtime.Now.Before(cert.NotAfter) {
			return "", "", ErrInvalid
		}
		for _, name := range names {
			if cert.VerifyHostname(name) != nil {
				return "", "", ErrInvalid
			}
		}
		data = m.CertificatePEM
		b.files[base+".key"] = append([]byte{}, m.KeyPEM...)
	}
	b.files[base+".pem"] = append([]byte{}, data...)
	return base + ".pem", base + ".key", nil
}
func prefixes(v []string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, s := range v {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return nil, ErrInvalid
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
func (b *builder) compileTarget(t app.Target) (target, error) {
	c := t.Config
	o := target{name: token(t.ID), config: c, endpoints: map[string]string{}, weights: map[string]int{}}
	if t.ID == "" || t.Revision < 1 || (c.Protocol != "http" && c.Protocol != "https") || len(c.Members) == 0 || len(c.Members) > 100 {
		return o, ErrInvalid
	}
	allow, e := prefixes(c.AllowedNetworks)
	if e != nil || len(allow) == 0 {
		return o, ErrInvalid
	}
	if c.HTTPHost != "" && !validName(c.HTTPHost) {
		return o, ErrInvalid
	}
	for _, m := range c.Members {
		if m.Port < 1 || m.Port > 65535 || m.Weight < 1 || m.Weight > 1000 {
			return o, ErrInvalid
		}
		name := ""
		if c.Protocol == "http" && m.TLSName != "" {
			return o, ErrInvalid
		}
		if c.Protocol == "https" {
			switch c.TLSNameMode {
			case "fixed":
				name = c.TLSName
			case "member":
				name = m.TLSName
				if name == "" {
					name = m.Address
				}
			default:
				return o, ErrInvalid
			}
			if !validName(name) {
				return o, ErrInvalid
			}
		}
		ips := []netip.Addr{}
		if ip, e := netip.ParseAddr(m.Address); e == nil {
			ips = append(ips, ip)
		} else {
			if !validName(m.Address) {
				return o, ErrInvalid
			}
			r, ok := b.runtime.Resolved[t.ID+"/"+m.Address]
			if !ok || r.TargetRevision != t.Revision || len(r.Addresses) == 0 || len(r.Addresses) > 100 {
				return o, ErrInvalid
			}
			ips = append(ips, r.Addresses...)
		}
		seen := map[string]bool{}
		for _, ip := range ips {
			if constrained.Check(ip, allow, b.runtime.ProtectedNetworks) != nil {
				return o, ErrInvalid
			}
			ep := net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(m.Port))
			if seen[ep] {
				continue
			}
			seen[ep] = true
			if prev, ok := o.endpoints[ep]; ok && prev != name {
				return o, ErrInvalid
			}
			if _, ok := o.endpoints[ep]; ok {
				return o, ErrInvalid
			}
			o.endpoints[ep] = name
			o.weights[ep] = m.Weight
			h, ok := b.runtime.Health[t.ID]
			if ok && h.TargetRevision != t.Revision {
				return o, ErrInvalid
			}
			if c.Health.Enabled && !ok {
				return o, ErrInvalid
			}
			if !ok || !h.Unhealthy[ep] {
				o.live = true
			} else {
				o.weights[ep] = 0
			}
		}
	}
	if c.Protocol == "https" {
		if (c.TLSServerNameMode != "" && c.TLSServerNameMode != "send" && c.TLSServerNameMode != "verify_only") || (c.TLSServerNameMode == "verify_only" && c.ClientCertificate == nil) {
			return o, ErrInvalid
		}
		o.trust, _, e = b.material(c.Trust, "trust", nil)
		if e != nil {
			return o, e
		}
		o.crl, e = b.crl(c.Trust)
		if e != nil {
			return o, e
		}
		if c.ClientCertificate != nil {
			o.clientCert, o.clientKey, e = b.material(c.ClientCertificate, "client", nil)
			if e != nil {
				return o, e
			}
		}
	} else if c.Trust != nil || c.ClientCertificate != nil || c.TLSName != "" || c.TLSNameMode != "" || c.TLSServerNameMode != "" {
		return o, ErrInvalid
	}
	return o, nil
}
func rateValid(r app.RatePolicy) bool {
	return r.RequestsPerSecond >= 0 && r.RequestsPerSecond <= 1000000 && r.Burst >= 0 && r.Burst <= 1000000 && r.Connections >= 0 && r.Connections <= 1000000 && (r.Status == 0 || r.Status == 429 || r.Status == 503)
}
func zones(w *strings.Builder, id string, r app.RatePolicy) {
	if r.RequestsPerSecond > 0 {
		fmt.Fprintf(w, "limit_req_zone $binary_remote_addr zone=%sr:1m rate=%dr/s;\n", id, r.RequestsPerSecond)
	}
	if r.Connections > 0 {
		fmt.Fprintf(w, "limit_conn_zone $binary_remote_addr zone=%sc:1m;\n", id)
	}
}
func limits(w *strings.Builder, id string, r app.RatePolicy) {
	if r.RequestsPerSecond > 0 {
		fmt.Fprintf(w, "limit_req zone=%sr", id)
		if r.Burst > 0 {
			fmt.Fprintf(w, " burst=%d nodelay", r.Burst)
		}
		w.WriteString(";\n")
	}
	if r.Connections > 0 {
		fmt.Fprintf(w, "limit_conn %sc %d;\n", id, r.Connections)
	}
}
func status(r app.RatePolicy) int {
	if r.Status == 503 {
		return 503
	}
	return 429
}
func cfNetworks(c app.CFPolicy, r edge.RuntimeState) ([]netip.Prefix, error) {
	if c.Mode == "" || c.Mode == "off" {
		if len(c.TrustedProxyNetworks) > 0 || c.RequireOriginPull {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	if c.Mode != "proxied" || r.Cloudflare.Generation == "" {
		return nil, ErrInvalid
	}
	narrow, e := prefixes(c.TrustedProxyNetworks)
	if e != nil {
		return nil, e
	}
	out := []netip.Prefix{}
	if r.Cloudflare.ValidUntil.IsZero() || r.Now.IsZero() || !r.Now.Before(r.Cloudflare.ValidUntil) {
		return out, nil
	}
	for _, p := range r.Cloudflare.Networks {
		if !p.IsValid() || p.Bits() == 0 {
			return nil, ErrInvalid
		}
		if len(narrow) == 0 {
			out = append(out, p.Masked())
			continue
		}
		for _, n := range narrow {
			if n.Addr().Is4() != p.Addr().Is4() {
				continue
			}
			if n.Contains(p.Addr()) {
				out = append(out, p.Masked())
			} else if p.Contains(n.Addr()) {
				out = append(out, n.Masked())
			}
		}
	}
	// An authoritative removal (including an empty user intersection) must
	// produce a closed site, so activation can retire previously trusted IPs.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
func (Compiler) Compile(s app.Snapshot, r edge.RuntimeState) (edge.Artifact, error) {
	if !version.MatchString(s.Version) || !version.MatchString(r.Generation) {
		return edge.Artifact{}, ErrInvalid
	}
	for _, g := range []string{r.DNSGeneration, r.HealthGeneration, r.CertificateGeneration, r.RevocationGeneration, r.Cloudflare.Generation} {
		if g != "" && !version.MatchString(g) {
			return edge.Artifact{}, ErrInvalid
		}
	}
	b := builder{files: map[string][]byte{}, runtime: r}
	usedCertificates := map[app.Material]bool{}
	w := &strings.Builder{}
	handshake := r.TLSHandshakeTimeoutSeconds
	if handshake == 0 {
		handshake = 10
	}
	if handshake < 1 || handshake > 30 {
		return edge.Artifact{}, ErrInvalid
	}
	fmt.Fprintf(w, "# DNS %s health %s certificates %s revocation %s Cloudflare %s\n", r.DNSGeneration, r.HealthGeneration, r.CertificateGeneration, r.RevocationGeneration, r.Cloudflare.Generation)
	logs := r.LogDirectory
	if logs == "" {
		logs = "/tmp"
	}
	if !regexp.MustCompile(`^/[a-zA-Z0-9/_-]+$`).MatchString(logs) || strings.Contains(logs, "//") {
		return edge.Artifact{}, ErrInvalid
	}
	// Request-scoped native errors can contain full query strings. Retain only
	// fixed structured access fields; master startup/reload errors keep their log.
	fmt.Fprintf(w, "# snapshot %s runtime %s\nworker_processes 1;\nworker_shutdown_timeout 30s;\npid /tmp/gatebeam-nginx.pid;\nerror_log %s/error.log warn;\nevents { worker_connections 1024; }\nhttp {\nerror_log /dev/null;\nclient_body_temp_path /tmp/gatebeam-body;\nproxy_temp_path /tmp/gatebeam-proxy;\nfastcgi_temp_path /tmp/gatebeam-fastcgi;\nuwsgi_temp_path /tmp/gatebeam-uwsgi;\nscgi_temp_path /tmp/gatebeam-scgi;\nmap $http_upgrade $connection_upgrade { default upgrade; '' close; }\nmap $host $edge_site { default ''; }\nmap $host $edge_route { default 'default'; }\nmap $host $edge_pattern { default '/'; }\nmap $host $edge_target { default ''; }\nmap $request_method $edge_method { default 'OTHER'; GET GET; HEAD HEAD; POST POST; PUT PUT; PATCH PATCH; DELETE DELETE; OPTIONS OPTIONS; CONNECT CONNECT; TRACE TRACE; }\nmap $upstream_status $edge_outcome { default 'error'; '' 'none'; '~^2[0-9][0-9]$' 'success'; '~^3[0-9][0-9]$' 'redirect'; '~^4[0-9][0-9]$' 'client_error'; '~^5[0-9][0-9]$' 'server_error'; }\n", s.Version, r.Generation, logs)
	fmt.Fprintf(w, "map $host $edge_config { default '%x'; }\n", sha256.Sum256([]byte(s.Version)))
	w.WriteString(`log_format edge escape=json '{"schema_version":1,"site_id":"$edge_site","request_id":"$request_id","time":"$time_iso8601","method":"$edge_method","path_pattern":"$edge_pattern","route":"$edge_route","config_id":"$edge_config","target_id":"$edge_target","upstream_outcome":"$edge_outcome","rate_req":"$limit_req_status","rate_conn":"$limit_conn_status","status":$status,"bytes_sent":$bytes_sent,"request_time":"$request_time"}';` + "\n")
	fmt.Fprintf(w, "access_log %s/access.log edge;\n", logs)
	fmt.Fprintf(w, "client_header_timeout %ds;\n", handshake)
	ts := append([]app.Target{}, s.Targets...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
	targets := map[string]target{}
	for _, t := range ts {
		if _, ok := targets[t.ID]; ok {
			return edge.Artifact{}, ErrInvalid
		}
		o, e := b.compileTarget(t)
		if e != nil {
			return edge.Artifact{}, fmt.Errorf("target %s: %w", t.ID, e)
		}
		targets[t.ID] = o
		eps := []string{}
		for ep := range o.endpoints {
			eps = append(eps, ep)
		}
		sort.Strings(eps)
		fmt.Fprintf(w, "upstream %s {\n", o.name)
		for _, ep := range eps {
			if o.weights[ep] > 0 {
				fmt.Fprintf(w, "server %s weight=%d;\n", ep, o.weights[ep])
			} else {
				fmt.Fprintf(w, "server %s down;\n", ep)
			}
		}
		w.WriteString("}\n")
		if o.config.Protocol == "https" {
			fmt.Fprintf(w, "map $upstream_addr $tls_%s { default unmapped.invalid;\n", o.name)
			for _, ep := range eps {
				fmt.Fprintf(w, "\"%s\" %s;\n", ep, o.endpoints[ep])
			}
			w.WriteString("}\n")
		}
	}
	sites := append([]app.Site{}, s.Sites...)
	sort.Slice(sites, func(i, j int) bool { return sites[i].ID < sites[j].ID })
	names := map[string]bool{}
	siteIDs := map[string]bool{}
	w.WriteString("map $ssl_server_name $sni_site { hostnames; default unknown;\n")
	for _, site := range sites {
		if !site.Config.Enabled {
			continue
		}
		if site.ID == "" || site.Revision < 1 || siteIDs[site.ID] {
			return edge.Artifact{}, ErrInvalid
		}
		siteIDs[site.ID] = true
		for _, d := range site.Config.Domains {
			if r.Management != nil && strings.EqualFold(d, r.Management.Domain) {
				return edge.Artifact{}, ErrInvalid
			}
			if !validName(d) || names[strings.ToLower(d)] {
				return edge.Artifact{}, ErrInvalid
			}
			names[strings.ToLower(d)] = true
			fmt.Fprintf(w, "%s %s;\n", strings.ToLower(d), token(site.ID))
		}
	}
	w.WriteString("}\n")
	challengeLocation := ""
	if r.ACMEWebRoot != "" {
		if !regexp.MustCompile(`^/[a-zA-Z0-9/_-]+$`).MatchString(r.ACMEWebRoot) || strings.Contains(r.ACMEWebRoot, "//") {
			return edge.Artifact{}, ErrInvalid
		}
		challengeLocation = fmt.Sprintf("location ^~ /.well-known/acme-challenge/ { root %s; default_type text/plain; limit_except GET { deny all; } try_files $uri =404; }\n", r.ACMEWebRoot)
	}
	fmt.Fprintf(w, "server { listen 8080 default_server; server_name _; %s location / { return 444; } }\nserver { listen 8443 ssl default_server; ssl_reject_handshake on; return 444; }\n", challengeLocation)
	fmt.Fprintf(w, "server { listen 127.0.0.1:9090; server_name _; access_log off; location = /version { default_type text/plain; return 200 '%s/%s'; } location / { return 404; } }\n", s.Version, r.Generation)
	for _, site := range sites {
		if !site.Config.Enabled {
			continue
		}
		c := site.Config
		id := token(site.ID)
		if len(c.Domains) == 0 || len(c.Routes) > 500 || !rateValid(c.Rate) {
			return edge.Artifact{}, ErrInvalid
		}
		zones(w, id, c.Rate)
		for i, route := range c.Routes {
			if route.Rate != nil {
				if !rateValid(*route.Rate) {
					return edge.Artifact{}, ErrInvalid
				}
				zones(w, fmt.Sprintf("%sp%d", id, i), *route.Rate)
			}
		}
		cf, e := cfNetworks(c.Cloudflare, r)
		if e != nil {
			return edge.Artifact{}, e
		}
		if len(cf) > 0 {
			expiry, e := cloudflareExpiryPattern(r.Cloudflare.ValidUntil)
			if e != nil {
				return edge.Artifact{}, e
			}
			fmt.Fprintf(w, "map $msec $cf_fresh_%s { volatile; default 0; %s 1; }\n", id, strconv.Quote("~"+expiry))
			fmt.Fprintf(w, "geo $realip_remote_addr $cf_%s { default 0;\n", id)
			for _, p := range cf {
				fmt.Fprintf(w, "%s 1;\n", p)
			}
			w.WriteString("}\n")
		}

		if len(c.Access.DenyPaths) > 0 {
			fmt.Fprintf(w, "map $uri $deny_%s { default 0;\n", id)
			for _, p := range c.Access.DenyPaths {
				if !safePath.MatchString(p) {
					return edge.Artifact{}, ErrInvalid
				}
				fmt.Fprintf(w, "%s 1;\n", strconv.Quote("~^"+regexp.QuoteMeta(p)))
			}
			w.WriteString("}\n")
		}
		if c.Maintenance.Enabled {
			message := c.Maintenance.Message
			if message == "" {
				message = "maintenance"
			}
			if len(message) > 1024 || strings.ContainsRune(message, 0) {
				return edge.Artifact{}, ErrInvalid
			}
			fmt.Fprintf(w, "geo $maintenance_%s { default %s; }\n", id, quoteLiteral(message))
		}
		cert, key := "", ""
		if c.EntryCertificate != nil {
			cert, key, e = b.material(c.EntryCertificate, "entry", c.Domains)
			if e != nil {
				return edge.Artifact{}, e
			}
			fmt.Fprintf(w, "server { listen 8080; server_name %s; %s location / { return 308 https://$host$request_uri; } }\n", strings.Join(c.Domains, " "), challengeLocation)
		}
		if !version.MatchString(site.ID) {
			return edge.Artifact{}, ErrInvalid
		}
		fmt.Fprintf(w, "server {\nserver_name %s;\nset $edge_site '%s';\n", strings.Join(c.Domains, " "), site.ID)
		if cert != "" {
			usedCertificates[app.Material{Kind: "certificate", ID: c.EntryCertificate.ID, Revision: c.EntryCertificate.Revision}] = true
			fmt.Fprintf(w, "listen 8443 ssl;\nssl_certificate %s;\nssl_certificate_key %s;\nssl_protocols TLSv1.2 TLSv1.3;\nssl_session_tickets off;\nif ($sni_site != %s) { return 421; }\n", cert, key, id)
		} else {
			w.WriteString("listen 8080;\n" + challengeLocation)
		}
		v := c.ClientVerification
		if v.Mode != "" && v.Mode != "off" {
			if cert == "" || (v.Mode != "required" && v.Mode != "optional") || v.Depth < 1 || v.Depth > 10 {
				return edge.Artifact{}, ErrInvalid
			}
			trust, _, e := b.material(v.Trust, "trust", nil)
			if e != nil {
				return edge.Artifact{}, e
			}
			fmt.Fprintf(w, "ssl_client_certificate %s;\nssl_verify_client %s;\nssl_verify_depth %d;\n", trust, map[string]string{"required": "on", "optional": "optional"}[v.Mode], v.Depth)
			m := r.Materials[v.Trust.ID]
			switch v.Revocation {
			case "crl", "crl_ocsp":
				path, e := b.crl(v.Trust)
				if e != nil {
					return edge.Artifact{}, e
				}
				fmt.Fprintf(w, "ssl_crl %s;\n", path)
			case "ocsp":
			default:
				return edge.Artifact{}, ErrInvalid
			}
			if v.Revocation == "ocsp" || v.Revocation == "crl_ocsp" {
				if validateOCSP(m, r) != nil {
					return edge.Artifact{}, ErrInvalid
				}
				w.WriteString("ssl_ocsp on;\nssl_ocsp_cache off;\n")
				if r.OCSPResponder != "" {
					if r.OCSPResponder != "http://127.0.0.1:9091/ocsp" {
						return edge.Artifact{}, ErrInvalid
					}
					w.WriteString("ssl_ocsp_responder http://127.0.0.1:9091/ocsp;\n")
				}
				writeOCSPResolver(w, r)
			}
		}
		if c.Cloudflare.RequireOriginPull && (v.Mode != "required" || v.Trust == nil || !r.Materials[v.Trust.ID].OriginPullAuthorized) {
			return edge.Artifact{}, ErrInvalid
		}
		if c.Cloudflare.Mode == "proxied" && len(cf) == 0 {
			w.WriteString("return 403;\n")
		}
		if len(cf) > 0 {
			for _, p := range cf {
				fmt.Fprintf(w, "set_real_ip_from %s;\n", p)
			}
			w.WriteString("real_ip_header CF-Connecting-IP;\nreal_ip_recursive off;\n")
			fmt.Fprintf(w, "if ($cf_%s = 0) { return 403; }\nif ($cf_fresh_%s = 0) { return 403; }\n", id, id)
		}
		if c.Maintenance.Enabled {
			if c.Maintenance.Status != 0 && c.Maintenance.Status != 503 {
				return edge.Artifact{}, ErrInvalid
			}
			fmt.Fprintf(w, "return 503 $maintenance_%s;\n", id)
		}
		for _, cidr := range c.Access.Deny {
			p, e := netip.ParsePrefix(cidr)
			if e != nil {
				return edge.Artifact{}, ErrInvalid
			}
			fmt.Fprintf(w, "deny %s;\n", p)
		}
		for _, cidr := range c.Access.Allow {
			p, e := netip.ParsePrefix(cidr)
			if e != nil {
				return edge.Artifact{}, ErrInvalid
			}
			fmt.Fprintf(w, "allow %s;\n", p)
		}
		if len(c.Access.Allow) > 0 {
			w.WriteString("deny all;\n")
		}
		paths := map[string]bool{}
		for _, p := range c.Access.DenyPaths {
			if !safePath.MatchString(p) || paths[p] {
				return edge.Artifact{}, ErrInvalid
			}
			paths[p] = true

		}
		if len(paths) > 0 {
			fmt.Fprintf(w, "if ($deny_%s = 1) { return 403; }\n", id)
		}
		conn := c.Connection
		if conn.ConnectTimeoutSeconds == 0 {
			conn.ConnectTimeoutSeconds = 5
		}
		if conn.ReadTimeoutSeconds == 0 {
			conn.ReadTimeoutSeconds = 60
		}
		if conn.SendTimeoutSeconds == 0 {
			conn.SendTimeoutSeconds = 60
		}
		if conn.MaxBodyBytes == 0 {
			conn.MaxBodyBytes = 10485760
		}
		if conn.ConnectTimeoutSeconds < 1 || conn.ConnectTimeoutSeconds > 300 || conn.ReadTimeoutSeconds < 1 || conn.ReadTimeoutSeconds > 3600 || conn.SendTimeoutSeconds < 1 || conn.SendTimeoutSeconds > 3600 || conn.MaxBodyBytes < 1 || conn.MaxBodyBytes > 1<<40 {
			return edge.Artifact{}, ErrInvalid
		}
		fmt.Fprintf(w, "client_max_body_size %d;\n", conn.MaxBodyBytes)
		seenRoutes := map[string]bool{}
		hasRoot := false
		for i, route := range c.Routes {
			if !safePath.MatchString(route.Path) || (route.Match != "prefix" && route.Match != "exact") || (route.StripPrefix && route.Match != "prefix") || seenRoutes[route.Match+route.Path] {
				return edge.Artifact{}, ErrInvalid
			}
			seenRoutes[route.Match+route.Path] = true
			if route.Path == "/" && route.Match == "prefix" {
				hasRoot = true
			}
			if e := writeLocation(w, id, i, c.Rate, route, targets, conn, usedCertificates); e != nil {
				return edge.Artifact{}, e
			}
		}
		if !hasRoot {

			if e := writeLocation(w, id, -1, c.Rate, app.Route{Match: "prefix", Path: "/", Target: c.DefaultTarget}, targets, conn, usedCertificates); e != nil {
				return edge.Artifact{}, e
			}
		}
		w.WriteString("}\n")
	}
	if e := b.management(w); e != nil {
		return edge.Artifact{}, e
	}
	w.WriteString("}\n")
	b.files["nginx.conf"] = []byte(w.String())
	keys := []string{}
	for k := range b.files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s:%d:", len(k), k, len(b.files[k]))
		h.Write(b.files[k])
	}
	digest := hex.EncodeToString(h.Sum(nil))
	refs := make([]app.Material, 0, len(usedCertificates))
	for ref := range usedCertificates {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID != refs[j].ID {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].Revision < refs[j].Revision
	})
	return edge.Artifact{ID: digest, Files: b.files, Digest: digest, CertificateRefs: refs}, nil
}
func writeLocation(w *strings.Builder, id string, i int, siteRate app.RatePolicy, route app.Route, targets map[string]target, c app.ConnectionPolicy, usedCertificates map[app.Material]bool) error {
	modifier := "^~"
	if route.Match == "exact" {
		modifier = "="
	}
	fmt.Fprintf(w, "location %s %s {\nset $edge_route '%d';\nset $edge_pattern '%s';\nset $edge_target '%s';\n", modifier, route.Path, i, route.Path, route.Target.ID)
	limits(w, id, siteRate)
	rstatus := status(siteRate)
	if route.Rate != nil {
		limits(w, fmt.Sprintf("%sp%d", id, i), *route.Rate)
		rstatus = status(*route.Rate)
	}
	fmt.Fprintf(w, "limit_req_status %d;\nlimit_conn_status %d;\n", rstatus, rstatus)
	t, ok := targets[route.Target.ID]
	if route.Target.ID == "" {
		w.WriteString("return 503;\n}\n")
		return nil
	}
	if !ok {
		return ErrInvalid
	}
	if !t.live {
		w.WriteString("return 503;\n}\n")
		return nil
	}
	host := "$http_host"
	if t.config.HTTPHost != "" {
		host = t.config.HTTPHost
	}
	fmt.Fprintf(w, "proxy_set_header Host %s;\nproxy_set_header X-Real-IP $remote_addr;\nproxy_set_header X-Forwarded-For $remote_addr;\nproxy_set_header X-Forwarded-Proto $scheme;\nproxy_set_header CF-Connecting-IP '';\nproxy_set_header Forwarded '';\nproxy_http_version 1.1;\nproxy_next_upstream off;\nproxy_connect_timeout %ds;\nproxy_read_timeout %ds;\nproxy_send_timeout %ds;\n", host, c.ConnectTimeoutSeconds, c.ReadTimeoutSeconds, c.SendTimeoutSeconds)
	if c.WebSocket {
		w.WriteString("proxy_set_header Upgrade $http_upgrade;\nproxy_set_header Connection $connection_upgrade;\n")
	} else {
		w.WriteString("proxy_set_header Upgrade '';\nproxy_set_header Connection '';\n")
	}
	if c.SSE || !c.BufferResponses {
		w.WriteString("proxy_buffering off;\n")
	}
	if t.config.Protocol == "https" {
		fmt.Fprintf(w, "proxy_ssl_verify on;\nproxy_ssl_verify_depth 5;\nproxy_ssl_server_name %s;\nproxy_ssl_session_reuse off;\nproxy_ssl_name $tls_%s;\nproxy_ssl_trusted_certificate %s;\n", map[bool]string{true: "off", false: "on"}[t.config.TLSServerNameMode == "verify_only"], t.name, t.trust)
		fmt.Fprintf(w, "proxy_ssl_crl %s;\n", t.crl)
		if t.clientCert != "" {
			usedCertificates[app.Material{Kind: "certificate", ID: t.config.ClientCertificate.ID, Revision: t.config.ClientCertificate.Revision}] = true
			fmt.Fprintf(w, "proxy_ssl_certificate %s;\nproxy_ssl_certificate_key %s;\n", t.clientCert, t.clientKey)
		}
	}
	suffix := ""
	if route.StripPrefix {
		suffix = "/"
	}
	fmt.Fprintf(w, "proxy_pass %s://%s%s;\n}\n", t.config.Protocol, t.name, suffix)
	return nil
}

// geo values are literal native strings, unlike complex-value return/map text.
// Referencing one variable once keeps user dollars from becoming Nginx variables.
func quoteLiteral(s string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r").Replace(s) + "\""
}
