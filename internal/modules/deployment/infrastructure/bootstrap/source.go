// Package bootstrap combines operator-owned management TLS with current owning
// application material and runtime bindings in the activation transaction.
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
	"io"
	"net/netip"
	"os"
	"slices"
	"time"
)

type Bindings interface {
	Prepare(context.Context, app.Snapshot) error
	BindWithin(transaction.Scope, app.Snapshot, edge.RuntimeState) (edge.RuntimeState, error)
}

type MaterialBindings interface {
	BindWithin(transaction.Scope, app.Snapshot, edge.RuntimeState) (edge.RuntimeState, error)
}

type CloudflareBindings interface {
	BindCloudflareWithin(transaction.Scope, app.Snapshot, edge.RuntimeState) (edge.RuntimeState, error)
}
type Source struct {
	UpstreamRenewedCertificateFile                                                                 string
	AdditionalAPIAddresses                                                                         []netip.AddrPort
	PeerAPIAddress                                                                                 netip.AddrPort
	UpstreamName, UpstreamTrustFile, UpstreamCertificateFile, UpstreamKeyFile, ManagementStateFile string
	ManagementACMEWebRoot, ManagementACMEHost                                                      string
	ACMEWebRoot                                                                                    string
	Cloudflare                                                                                     CloudflareBindings
	Materials                                                                                      MaterialBindings
	Bindings                                                                                       Bindings
	Domain, CertificateFile, KeyFile, TrustFile, LogDirectory                                      string
	APIAddress                                                                                     netip.AddrPort
	ProtectedNetworks                                                                              []netip.Prefix
}

func read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("management bootstrap material unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("invalid management bootstrap material")
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
func (s *Source) ReadWithin(sc transaction.Scope, snapshot app.Snapshot) (edge.RuntimeState, error) {
	if sc == nil || sc.Context().Err() != nil {
		return edge.RuntimeState{}, errors.New("current runtime scope unavailable")
	}
	// All providers perform network-free authoritative reads in the supplied scope.
	if s.Materials == nil && len(release.Requirements(snapshot)) > 0 {
		return edge.RuntimeState{}, domain.ErrUnavailable
	}
	for _, site := range snapshot.Sites {
		if s.Cloudflare == nil && site.Config.Cloudflare.Mode == "proxied" {
			return edge.RuntimeState{}, domain.ErrUnavailable
		}
	}
	cert, e := read(s.CertificateFile)
	if e != nil {
		return edge.RuntimeState{}, e
	}
	key, e := read(s.KeyFile)
	if e != nil {
		return edge.RuntimeState{}, e
	}
	trust, e := read(s.TrustFile)
	if e != nil {
		return edge.RuntimeState{}, e
	}
	management := &edge.ManagementTLS{Domain: s.Domain, APIAddress: s.APIAddress, CertificatePEM: cert, KeyPEM: key, TrustPEM: trust}
	if s.UpstreamName != "" || s.PeerAPIAddress.IsValid() || len(s.AdditionalAPIAddresses) > 0 {
		upstreamTrust, e := read(s.UpstreamTrustFile)
		if e != nil {
			return edge.RuntimeState{}, e
		}
		certificateFile := s.UpstreamCertificateFile
		if s.UpstreamRenewedCertificateFile != "" {
			if _, err := os.Lstat(s.UpstreamRenewedCertificateFile); err == nil {
				certificateFile = s.UpstreamRenewedCertificateFile
			}
		}
		upstreamCert, e := read(certificateFile)
		if e != nil {
			return edge.RuntimeState{}, e
		}
		upstreamKey, e := read(s.UpstreamKeyFile)
		if e != nil {
			return edge.RuntimeState{}, e
		}
		management.PeerAPIAddress = s.PeerAPIAddress
		management.UpstreamTLS = &edge.ManagementUpstreamTLS{ServerName: s.UpstreamName, TrustPEM: upstreamTrust, CertificatePEM: upstreamCert, KeyPEM: upstreamKey}
		maintenance, e := ReadManagementState(s.ManagementStateFile, s.APIAddress, s.PeerAPIAddress, s.AdditionalAPIAddresses...)
		if e != nil {
			return edge.RuntimeState{}, e
		}
		management.AdditionalAPIAddresses = slices.Clone(s.AdditionalAPIAddresses)
		for _, address := range maintenance.DynamicPeers {
			peer, err := netip.ParseAddrPort(address)
			if err != nil || !slices.ContainsFunc(s.ProtectedNetworks, func(prefix netip.Prefix) bool { return prefix.Contains(peer.Addr()) }) {
				return edge.RuntimeState{}, domain.ErrInvalid
			}
			management.AdditionalAPIAddresses = append(management.AdditionalAPIAddresses, peer)
		}
		for _, address := range maintenance.Unavailable {
			switch address {
			case s.APIAddress.String():
				management.APIUnavailable = true
			case s.PeerAPIAddress.String():
				management.PeerUnavailable = true
			default:
				target, err := netip.ParseAddrPort(address)
				if err != nil {
					return edge.RuntimeState{}, err
				}
				management.UnavailableAPIAddresses = append(management.UnavailableAPIAddresses, target)
			}
		}
		management.ConfigurationDigest = maintenance.Digest()
	}
	h := sha256.New()
	h.Write(cert)
	h.Write(trust)
	h.Write([]byte(s.Domain + s.APIAddress.String()))
	managementBytes, _ := json.Marshal(management)
	h.Write(managementBytes)
	generation := hex.EncodeToString(h.Sum(nil))
	state := edge.RuntimeState{ACMEWebRoot: s.ACMEWebRoot, ManagementACMEWebRoot: s.ManagementACMEWebRoot, ManagementACMEHost: s.ManagementACMEHost, Generation: generation, CertificateGeneration: generation, Now: time.Now(), LogDirectory: s.LogDirectory, ProtectedNetworks: s.ProtectedNetworks, Management: management}
	if s.Materials != nil {
		state, e = s.Materials.BindWithin(sc, snapshot, state)
		if e != nil {
			return state, e
		}
	}
	if s.Cloudflare != nil {
		state, e = s.Cloudflare.BindCloudflareWithin(sc, snapshot, state)
		if e != nil {
			return state, e
		}
	}
	if s.Bindings != nil {
		return s.Bindings.BindWithin(sc, snapshot, state)
	}
	if len(snapshot.Targets) > 0 {
		return edge.RuntimeState{}, domain.ErrUnavailable
	}
	return state, nil
}

// Prepare performs only bounded private DNS binding outside authority transactions.
func (s *Source) Prepare(ctx context.Context, snapshot app.Snapshot) error {
	if s.Bindings == nil {
		if len(snapshot.Targets) > 0 {
			return domain.ErrUnavailable
		}
		return nil
	}
	return s.Bindings.Prepare(ctx, snapshot)
}
