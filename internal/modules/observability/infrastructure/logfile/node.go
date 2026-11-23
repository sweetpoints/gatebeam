package logfile

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"github.com/google/uuid"
	"io"
	"os"
	"strings"
)

type volumeIdentity struct {
	Version          int `json:"version"`
	NodeID, VolumeID string
}

func validNode(id string) bool {
	return domain.ValidSite(id) && id != "00000000-0000-0000-0000-000000000000"
}

// InitializeNodeVolume is controlled initialization for a fresh log volume.
// Existing nonempty legacy logs require a separate proved ownership migration.
func InitializeNodeVolume(path, node string) error {
	if !validNode(node) {
		return domain.ErrInvalid
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return e
	}
	defer root.Close()
	if existing, e := readVolume(root); e == nil {
		if existing.NodeID == node {
			return nil
		}
		return domain.ErrSourceChanged
	} else if !os.IsNotExist(e) {
		return e
	}
	directory, e := root.Open(".")
	if e != nil {
		return e
	}
	defer directory.Close()
	entries, e := directory.ReadDir(2049)
	if e != nil && e != io.EOF {
		return e
	}
	if len(entries) > 2048 {
		return domain.ErrCapacity
	}
	for _, entry := range entries {
		if names.MatchString(entry.Name()) || strings.HasPrefix(entry.Name(), "error") && strings.HasSuffix(entry.Name(), ".log") {
			info, e := root.Lstat(entry.Name())
			if e != nil || !info.Mode().IsRegular() || info.Size() > 0 {
				return domain.ErrSourceChanged
			}
		}
	}
	body, _ := json.Marshal(volumeIdentity{Version: 1, NodeID: node, VolumeID: uuid.NewString()})
	file, e := root.OpenFile(".gatebeam-node.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = file.Write(body)
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return directory.Sync()
}
func readVolume(root *os.Root) (v volumeIdentity, err error) {
	info, e := root.Lstat(".gatebeam-node.json")
	if e != nil {
		return v, e
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 || info.Mode().Perm()&0077 != 0 {
		return v, domain.ErrSourceChanged
	}
	file, e := root.Open(".gatebeam-node.json")
	if e != nil {
		return v, e
	}
	defer file.Close()
	actual, e := file.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return v, domain.ErrSourceChanged
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&v); e != nil {
		return v, e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || v.Version != 1 || !validNode(v.NodeID) || !validNode(v.VolumeID) {
		return v, domain.ErrSourceChanged
	}
	return
}
func OpenNode(path, node string) (*Source, error) {
	if !validNode(node) {
		return nil, domain.ErrInvalid
	}
	source, e := Open(path)
	if e != nil {
		return nil, e
	}
	identity, e := readVolume(source.root)
	if e != nil || identity.NodeID != node {
		source.Close()
		return nil, domain.ErrSourceChanged
	}
	source.nodeID = node
	source.volumeID = identity.VolumeID
	return source, nil
}
func (s *Source) identity(file *os.File, closed bool) (domain.Segment, error) {
	segment, e := identity(file, closed)
	if e != nil {
		return segment, e
	}
	if s.nodeID != "" {
		segment.NodeID = s.nodeID
		segment.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(s.nodeID+"/"+s.volumeID+"/"+segment.ID)))
	} else {
		segment.NodeID = "legacy"
	}
	return segment, nil
}
