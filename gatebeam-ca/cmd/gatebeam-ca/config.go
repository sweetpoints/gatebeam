package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
)

type config struct {
	DatabaseFile            string   `json:"database_file"`
	Listen                  string   `json:"listen"`
	Origin                  string   `json:"origin"`
	StatusListen            string   `json:"status_listen"`
	StatusOrigin            string   `json:"status_origin"`
	TLSCertificateFile      string   `json:"tls_certificate_file"`
	TLSKeyFile              string   `json:"tls_key_file"`
	TLSTrustFile            string   `json:"tls_trust_file"`
	IssuerFile              string   `json:"issuer_file"`
	RootFile                string   `json:"root_file"`
	SignerFile              string   `json:"signer_file"`
	IdentityFile            string   `json:"identity_file"`
	RootCRLFile             string   `json:"root_crl_file"`
	RootOCSPCertificateFile string   `json:"root_ocsp_certificate_file"`
	RootOCSPSignerFile      string   `json:"root_ocsp_signer_file"`
	Recipient               string   `json:"recipient"`
	Recipients              []string `json:"recipients"`
	ServerNames             []string `json:"server_names"`
	ClientNames             []string `json:"client_names"`
	ValidationNetworks      []string `json:"validation_networks"`
	ValidationDenyNetworks  []string `json:"validation_deny_networks"`
}

func readConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	const maxSize = 1 << 20
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSize {
		return c, errors.New("config must be a regular file of at most 1 MiB")
	}
	d := json.NewDecoder(io.LimitReader(f, maxSize+1))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("decode config: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("config must contain one JSON object")
	}
	return c, nil
}

func privateListen(value string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || addr.Port() == 0 || (!addr.Addr().IsPrivate() && !addr.Addr().IsLoopback()) {
		return netip.AddrPort{}, errors.New("listener must bind an explicit private or loopback IP and nonzero port")
	}
	return addr, nil
}

func originHost(value, scheme string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != scheme || u.Hostname() == "" || u.User != nil || value != scheme+"://"+u.Host {
		return "", fmt.Errorf("expected a canonical %s origin", scheme)
	}
	return u.Hostname(), nil
}
