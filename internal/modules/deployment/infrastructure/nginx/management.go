package nginx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

func (b *builder) management(w *strings.Builder) error {
	m := b.runtime.Management
	if m == nil {
		return nil
	}
	if !validName(m.Domain) || !m.APIAddress.IsValid() || !m.APIAddress.Addr().IsPrivate() || (m.APIAddress.Port() != 8080 && m.UpstreamTLS == nil) || b.runtime.Now.IsZero() {
		return ErrInvalid
	}
	pair, e := tls.X509KeyPair(m.CertificatePEM, m.KeyPEM)
	if e != nil || len(pair.Certificate) == 0 {
		return ErrInvalid
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.TrustPEM) {
		return ErrInvalid
	}
	chain := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return ErrInvalid
		}
		chain.AddCert(c)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{DNSName: m.Domain, Roots: roots, Intermediates: chain, CurrentTime: b.runtime.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return ErrInvalid
	}
	b.files["materials/management.pem"] = append([]byte{}, m.CertificatePEM...)
	b.files["materials/management.key"] = append([]byte{}, m.KeyPEM...)

	proxy := "proxy_next_upstream off;\n  proxy_pass http://" + m.APIAddress.String() + ";"
	peers := slices.Clone(m.AdditionalAPIAddresses)
	if m.PeerAPIAddress.IsValid() {
		peers = append([]netip.AddrPort{m.PeerAPIAddress}, peers...)
	}
	if len(peers) > 0 || m.UpstreamTLS != nil {
		if m.UpstreamTLS == nil {
			return ErrInvalid
		}
		configured := map[netip.AddrPort]bool{m.APIAddress: true}
		for _, peer := range peers {
			if !peer.Addr().IsPrivate() || peer.Port() == 0 || configured[peer] {
				return ErrInvalid
			}
			configured[peer] = true
		}
		for _, unavailable := range m.UnavailableAPIAddresses {
			if !configured[unavailable] {
				return ErrInvalid
			}
		}
		policy := m.UpstreamTLS
		if !validName(policy.ServerName) {
			return ErrInvalid
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(policy.TrustPEM) {
			return ErrInvalid
		}
		pair, e := tls.X509KeyPair(policy.CertificatePEM, policy.KeyPEM)
		if e != nil || len(pair.Certificate) == 0 {
			return ErrInvalid
		}
		client, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil || client.IsCA {
			return ErrInvalid
		}
		chain := x509.NewCertPool()
		for _, der := range pair.Certificate[1:] {
			c, e := x509.ParseCertificate(der)
			if e != nil {
				return ErrInvalid
			}
			chain.AddCert(c)
		}
		if _, e = client.Verify(x509.VerifyOptions{Roots: roots, Intermediates: chain, CurrentTime: b.runtime.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			return ErrInvalid
		}
		b.files["materials/management-upstream-trust.pem"] = append([]byte{}, policy.TrustPEM...)
		b.files["materials/management-upstream.pem"] = append([]byte{}, policy.CertificatePEM...)
		b.files["materials/management-upstream.key"] = append([]byte{}, policy.KeyPEM...)
		primaryAvailable := !m.APIUnavailable && !slices.Contains(m.UnavailableAPIAddresses, m.APIAddress)
		availablePeers := make([]netip.AddrPort, 0, len(peers))
		for _, peer := range peers {
			if (peer == m.PeerAPIAddress && m.PeerUnavailable) || slices.Contains(m.UnavailableAPIAddresses, peer) {
				continue
			}
			availablePeers = append(availablePeers, peer)
		}
		if !primaryAvailable && len(availablePeers) == 0 {
			proxy = "return 503;"
		} else {
			w.WriteString("upstream gatebeam_management {\n")
			backup := ""
			if primaryAvailable {
				fmt.Fprintf(w, " server %s max_fails=1 fail_timeout=2s;\n", m.APIAddress)
				backup = " backup"
			}
			for _, peer := range availablePeers {
				fmt.Fprintf(w, " server %s%s max_fails=1 fail_timeout=2s;\n", peer, backup)
			}
			w.WriteString("}\n")
			proxy = fmt.Sprintf(`proxy_next_upstream error timeout;
  proxy_next_upstream_tries 2;
  proxy_next_upstream_timeout 4s;
  proxy_ssl_verify on;
  proxy_ssl_verify_depth 4;
  proxy_ssl_server_name on;
  proxy_ssl_name %s;
  proxy_ssl_trusted_certificate materials/management-upstream-trust.pem;
  proxy_ssl_certificate materials/management-upstream.pem;
  proxy_ssl_certificate_key materials/management-upstream.key;
  proxy_ssl_protocols TLSv1.2 TLSv1.3;
  proxy_pass https://gatebeam_management;`, policy.ServerName)
		}
	} else if m.APIUnavailable {
		proxy = "return 503;"
	}
	fmt.Fprintf(w, `server {
 listen 8443 ssl;
 server_name %s;
 ssl_certificate materials/management.pem;
 ssl_certificate_key materials/management.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 ssl_session_tickets off;
 if ($ssl_server_name != %s) { return 421; }
 if ($host != %s) { return 421; }
 set $edge_site 'management';
 location = /_gatebeam/ready { access_log off; default_type text/plain; return 200 'management-ready'; }
 location / {
  proxy_set_header Host %s;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header Forwarded '';
  proxy_connect_timeout 2s;
  proxy_read_timeout 15s;
  proxy_send_timeout 15s;
  %s
 }
}
`, m.Domain, m.Domain, m.Domain, m.Domain, proxy)
	return nil
}
