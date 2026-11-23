package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

type ManagementState struct {
	Revision    uint64   `json:"revision"`
	Unavailable []string `json:"unavailable"`
}

func (s ManagementState) Digest() string {
	if s.Unavailable == nil {
		s.Unavailable = []string{}
	}
	body, _ := json.Marshal(s)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func ReadManagementState(path string, primary, peer netip.AddrPort) (out ManagementState, err error) {
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
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return out, errors.New("invalid management maintenance state")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&out); e != nil {
		return out, e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(out.Unavailable) > 2 || out.Revision == 0 {
		return out, errors.New("invalid management maintenance state")
	}
	seen := map[string]bool{}
	for _, address := range out.Unavailable {
		if seen[address] || (address != primary.String() && address != peer.String()) {
			return out, errors.New("unknown management maintenance target")
		}
		seen[address] = true
	}
	sort.Strings(out.Unavailable)
	return out, nil
}

// UpdateManagementState is operator-only representation input. It never applies
// native state; the ordinary derived compiler/authority/native confirmation
// path must load and acknowledge this revision before an API may be stopped.
func UpdateManagementState(path string, primary, peer netip.AddrPort, address string, unavailable bool) (out ManagementState, err error) {
	if path == "" || (address != primary.String() && address != peer.String()) {
		return out, errors.New("unknown management maintenance target")
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
	out, e = ReadManagementState(path, primary, peer)
	if e != nil {
		return out, e
	}
	next := []string{}
	present := false
	for _, v := range out.Unavailable {
		if v == address {
			present = true
			if !unavailable {
				continue
			}
		}
		next = append(next, v)
	}
	if unavailable && !present {
		next = append(next, address)
	}
	if present == unavailable {
		return out, nil
	}
	if out.Revision == ^uint64(0) {
		return out, errors.New("management revision exhausted")
	}
	out.Revision++
	out.Unavailable = next
	sort.Strings(out.Unavailable)
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
func InitializeManagementState(path string, primary, peer netip.AddrPort) (ManagementState, error) {
	if path == "" || !primary.IsValid() || !peer.IsValid() || !primary.Addr().IsPrivate() || !peer.Addr().IsPrivate() || primary == peer || primary.Port() == 0 || peer.Port() == 0 {
		return ManagementState{}, errors.New("two private management targets required")
	}
	if _, e := os.Lstat(path); e == nil {
		return ReadManagementState(path, primary, peer)
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
		return ReadManagementState(path, primary, peer)
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
