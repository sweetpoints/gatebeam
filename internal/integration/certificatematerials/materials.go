// Package certificatematerials maps only exported owning application contracts.
package certificatematerials

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	cert "gatebeam/internal/modules/certificates/application"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/platform/transaction"
	"net/netip"
	"sort"
)

type Owner interface {
	ValidateMaterialsWithin(transaction.Scope, []cert.MaterialRef) error
	ReadMaterialsWithin(transaction.Scope, []cert.MaterialRef) (cert.Materials, error)
}
type Adapter struct {
	Owner   Owner
	Offline *OfflineStatus
}

func refs(in []deploy.Material) []cert.MaterialRef {
	out := []cert.MaterialRef{}
	for _, v := range in {
		out = append(out, cert.MaterialRef{ID: v.ID, Kind: v.Kind, Revision: v.Revision})
	}
	return out
}
func requirements(in []deploy.MaterialRequirement) []cert.MaterialRef {
	out := []cert.MaterialRef{}
	for _, v := range in {
		out = append(out, cert.MaterialRef{ID: v.Ref.ID, Kind: v.Ref.Kind, Revision: v.Ref.Revision, Names: v.Names, Purpose: v.Usage})
	}
	return out
}
func discard(m cert.Materials) {
	for _, v := range m.Items {
		clear(v.KeyPEM)
	}
}
func (a Adapter) ReadMaterialsWithin(sc transaction.Scope, in []deploy.Material) error {
	return a.Owner.ValidateMaterialsWithin(sc, refs(in))
}
func (a Adapter) ValidateHistoricalWithin(sc transaction.Scope, in []deploy.MaterialRequirement) error {
	return a.Owner.ValidateMaterialsWithin(sc, requirements(in))
}
func (a Adapter) BindWithin(sc transaction.Scope, s deploy.Snapshot, state edge.RuntimeState) (edge.RuntimeState, error) {
	materials, e := a.Owner.ReadMaterialsWithin(sc, requirements(release.Requirements(s)))
	if e != nil {
		return state, e
	}
	state.Materials = map[string]edge.Material{}
	profileGenerations := map[string]bool{}
	for _, m := range materials.Items {
		v := edge.Material{VersionID: m.Version.ID, Digest: m.Version.Digest, Revision: m.Ref.Revision, CertificatePEM: m.CertificatePEM, KeyPEM: m.KeyPEM, TrustPEM: m.TrustPEM, CRLPEM: m.CRLPEM, OriginPullAuthorized: m.OriginPullAuthorized}
		if m.Status != nil {
			v.OCSP = &edge.OCSPState{Generation: m.Status.Generation, ValidUntil: m.Status.ValidUntil, ResponderNames: m.Status.ResponderNames}
			v.CRLPEM = m.Status.CRLPEM
			servers := []netip.AddrPort{}
			for _, raw := range m.Status.ResolverServers {
				server, e := netip.ParseAddrPort(raw)
				if e != nil {
					return state, e
				}
				servers = append(servers, server)
			}
			profileGenerations[m.Status.ProfileDigest] = true
			resolver := &edge.ResolverState{Servers: servers, TimeoutSeconds: 2, ValidForSeconds: 30}
			if state.OCSPResolver != nil {
				effective := *state.OCSPResolver
				effective.Generation = ""
				old, _ := json.Marshal(effective)
				fresh, _ := json.Marshal(resolver)
				if string(old) != string(fresh) {
					return state, errors.New("incompatible trusted resolver profiles")
				}
			}
			state.OCSPResolver = resolver
			state.TLSHandshakeTimeoutSeconds = 10
			state.RevocationGeneration = materials.Generation
		}
		state.Materials[m.Ref.ID] = v
	}
	if state.OCSPResolver != nil {
		profiles := make([]string, 0, len(profileGenerations))
		for profile := range profileGenerations {
			profiles = append(profiles, profile)
		}
		sort.Strings(profiles)
		data, _ := json.Marshal(profiles)
		sum := sha256.Sum256(data)
		state.OCSPResolver.Generation = hex.EncodeToString(sum[:])
	}
	state.CertificateGeneration = materials.Generation
	b, _ := json.Marshal([]string{state.Generation, materials.Generation})
	hash := sha256.Sum256(b)
	state.Generation = hex.EncodeToString(hash[:])
	if err := a.Offline.Bind(&state); err != nil {
		return state, err
	}
	return state, nil
}
