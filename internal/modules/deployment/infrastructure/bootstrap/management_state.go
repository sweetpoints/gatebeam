package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"syscall"
)

type ManagementState struct {
	Revision     uint64   `json:"revision"`
	Unavailable  []string `json:"unavailable"`
	DynamicPeers []string `json:"dynamic_peers,omitempty"`
}

func (s ManagementState) Digest() string {
	if s.Unavailable == nil {
		s.Unavailable = []string{}
	}
	body, _ := json.Marshal(s)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func knownManagementAddress(address string, primary, peer netip.AddrPort, additional []netip.AddrPort) bool {
	target, err := netip.ParseAddrPort(address)
	return err == nil && (target == primary || target == peer || slices.Contains(additional, target)) && address == target.String()
}

func ReadManagementState(path string, primary, peer netip.AddrPort, additional ...netip.AddrPort) (out ManagementState, err error) {
	out.Unavailable = []string{}
	if path == "" {
		return out, nil
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return out, errors.New("management maintenance state unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return out, errors.New("invalid management maintenance state")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&out); e != nil {
		return out, e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || out.Revision == 0 ||
		len(out.Unavailable) > domain.MaxFleetNodes || len(out.DynamicPeers)+len(additional) > domain.MaxFleetNodes-1 ||
		(peer.IsValid() && len(out.DynamicPeers)+len(additional) > domain.MaxFleetNodes-2) {
		return out, errors.New("invalid management maintenance state")
	}
	allowed := slices.Clone(additional)
	for _, address := range out.DynamicPeers {
		parsed, err := netip.ParseAddrPort(address)
		if err != nil || !parsed.Addr().IsPrivate() || parsed.Port() != primary.Port() || parsed.String() != address ||
			knownManagementAddress(address, primary, peer, allowed) {
			return out, errors.New("invalid dynamic management peer")
		}
		allowed = append(allowed, parsed)
	}
	seen := map[string]bool{}
	for _, address := range out.Unavailable {
		if seen[address] || !knownManagementAddress(address, primary, peer, allowed) {
			return out, errors.New("unknown management maintenance target")
		}
		seen[address] = true
	}
	sort.Strings(out.Unavailable)
	sort.Strings(out.DynamicPeers)
	return out, nil
}

// UpdateManagementState is operator-only representation input. It never applies
// native state; the ordinary derived compiler/authority/native confirmation
// path must load and acknowledge this revision before an API may be stopped.
func UpdateManagementState(path string, primary, peer netip.AddrPort, address string, unavailable bool, additional ...netip.AddrPort) (ManagementState, error) {
	return changeManagementState(path, primary, peer, additional, func(state *ManagementState) (bool, error) {
		if !knownManagementAddress(address, primary, peer, additional) && !slices.Contains(state.DynamicPeers, address) {
			return false, errors.New("unknown management maintenance target")
		}
		if slices.Contains(state.Unavailable, address) == unavailable {
			return false, nil
		}
		if unavailable {
			state.Unavailable = append(state.Unavailable, address)
		} else {
			state.Unavailable = slices.DeleteFunc(state.Unavailable, func(entry string) bool { return entry == address })
		}
		return true, nil
	})
}

// RegisterManagementPeer stages a new endpoint inside an existing protection
// boundary. Only a separate maintenance confirmation can start routing to it.
func RegisterManagementPeer(path string, primary, peer netip.AddrPort, address string, protected []netip.Prefix, additional ...netip.AddrPort) (ManagementState, error) {
	target, err := netip.ParseAddrPort(address)
	if err != nil || target.String() != address || target.Port() != primary.Port() || !target.Addr().IsPrivate() ||
		!slices.ContainsFunc(protected, func(prefix netip.Prefix) bool { return prefix.Contains(target.Addr()) }) ||
		knownManagementAddress(address, primary, peer, additional) {
		return ManagementState{}, errors.New("new management endpoint must be in an existing protected network")
	}
	return changeManagementState(path, primary, peer, additional, func(state *ManagementState) (bool, error) {
		if slices.Contains(state.DynamicPeers, address) {
			return false, nil
		}
		total := 1 + len(additional) + len(state.DynamicPeers)
		if peer.IsValid() {
			total++
		}
		if total >= domain.MaxFleetNodes {
			return false, errors.New("too many management peers")
		}
		state.DynamicPeers = append(state.DynamicPeers, address)
		state.Unavailable = append(state.Unavailable, address)
		return true, nil
	})
}

func changeManagementState(path string, primary, peer netip.AddrPort, additional []netip.AddrPort, change func(*ManagementState) (bool, error)) (out ManagementState, err error) {
	if path == "" {
		return out, errors.New("management maintenance state unavailable")
	}
	parent := filepath.Dir(path)
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil || resolved != parent {
		return out, errors.New("management state directory must be canonical")
	}
	fd, e := syscall.Open(path+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return out, e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return out, e
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	out, e = ReadManagementState(path, primary, peer, additional...)
	if e != nil {
		return out, e
	}
	changed, e := change(&out)
	if e != nil || !changed {
		return out, e
	}
	if out.Revision == ^uint64(0) {
		return out, errors.New("management revision exhausted")
	}
	out.Revision++
	sort.Strings(out.Unavailable)
	sort.Strings(out.DynamicPeers)
	body, _ := json.Marshal(out)
	temp, e := os.CreateTemp(parent, ".management-")
	if e != nil {
		return out, e
	}
	defer os.Remove(temp.Name())
	if e = temp.Chmod(0600); e == nil {
		_, e = temp.Write(body)
	}
	if e == nil {
		e = temp.Sync()
	}
	e = errors.Join(e, temp.Close())
	if e != nil {
		return out, e
	}
	if e = os.Rename(temp.Name(), path); e != nil {
		return out, e
	}
	dir, e := os.Open(parent)
	if e != nil {
		return out, e
	}
	defer dir.Close()
	return out, dir.Sync()
}

// InitializeManagementState creates the initial protected state before a cold
// enrollment preview. Existing exclusions/revisions are read, never reset.
func InitializeManagementState(path string, primary, peer netip.AddrPort, additional ...netip.AddrPort) (ManagementState, error) {
	if path == "" || !primary.Addr().IsPrivate() || primary.Port() == 0 {
		return ManagementState{}, errors.New("private management target required")
	}
	seen := map[netip.AddrPort]bool{primary: true}
	addresses := additional
	if peer.IsValid() {
		addresses = append([]netip.AddrPort{peer}, additional...)
	}
	for _, address := range addresses {
		if !address.Addr().IsPrivate() || address.Port() == 0 || seen[address] {
			return ManagementState{}, errors.New("invalid private management target")
		}
		seen[address] = true
	}
	if _, e := os.Lstat(path); e == nil {
		return ReadManagementState(path, primary, peer, additional...)
	} else if !os.IsNotExist(e) {
		return ManagementState{}, e
	}
	parent := filepath.Dir(path)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent {
		return ManagementState{}, errors.New("canonical private control directory required")
	}
	info, e := os.Lstat(parent)
	if e != nil {
		return ManagementState{}, e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || int(stat.Uid) != os.Geteuid() {
		return ManagementState{}, errors.New("owned private control directory required")
	}
	state := ManagementState{Revision: 1, Unavailable: []string{}}
	body, _ := json.Marshal(state)
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(e) {
		return ReadManagementState(path, primary, peer, additional...)
	}
	if e != nil {
		return ManagementState{}, e
	}
	_, e = file.Write(body)
	if e == nil {
		e = file.Sync()
	}
	e = errors.Join(e, file.Close())
	if e != nil {
		return ManagementState{}, e
	}
	directory, e := os.Open(parent)
	if e != nil {
		return ManagementState{}, e
	}
	defer directory.Close()
	if e = directory.Sync(); e != nil {
		return ManagementState{}, e
	}
	return state, nil
}
