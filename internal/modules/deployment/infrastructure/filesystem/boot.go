package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	runtime "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/safety"
	"io"
	stdfs "io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"
)

const maxBootMetadata = 8 << 20

type bootRecord struct {
	Manifest   domain.BootManifest
	Plan       runtime.Plan
	SourcePlan *runtime.Plan
}

type bootCheckpoint struct {
	Current        runtime.BootEvidence
	Previous       runtime.BootEvidence
	MinimumFloor   domain.SecurityFloor
	ReceiptPending bool
}

var _ runtime.BootStore = (*Store)(nil)

func (s *Store) bootDirectories() error {
	for _, dir := range []string{s.root, filepath.Join(s.root, "releases")} {
		if err := secureInfo(dir, true); err != nil {
			return err
		}
	}
	for _, dir := range []string{filepath.Join(s.root, "boot"), filepath.Join(s.root, "boot", "staged")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := secureInfo(dir, true); err != nil {
			return err
		}
	}
	return syncDir(s.root)
}

func secureInfo(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return domain.ErrInvalid
	}
	return nil
}

func secureRead(path string, limit int64) ([]byte, error) {
	if err := secureInfo(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, domain.ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, domain.ErrInvalid
	}
	return b, nil
}

func decodeBoot(path string, v any) error {
	b, err := secureRead(path, maxBootMetadata)
	if err != nil {
		return err
	}
	return decodeBootBytes(b, v)
}

func decodeBootBytes(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return domain.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return domain.ErrInvalid
	}
	return nil
}

func (s *Store) bootLock(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.bootDirectories(); err != nil {
		return nil, err
	}
	return s.lockFile(ctx, "boot.lock")
}

func (s *Store) floor() (domain.SecurityFloor, error) {
	var floor domain.SecurityFloor
	if err := decodeBoot(filepath.Join(s.root, "boot", "floor.json"), &floor); err != nil {
		return floor, err
	}
	return floor, floor.Validate()
}

func (s *Store) StageConfirmed(ctx context.Context, b runtime.BootBundle) error {
	if b.Manifest.Validate() != nil || len(b.Files["nginx.conf"]) == 0 {
		return domain.ErrInvalid
	}
	unlock, err := s.bootLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	id, err := artifactDigest(b.Files)
	if err != nil || id != b.Manifest.ArtifactID {
		return domain.ErrInvalid
	}
	b.Manifest.FileDigests = make(map[string]string, len(b.Files))
	for name, contents := range b.Files {
		digest := sha256.Sum256(contents)
		b.Manifest.FileDigests[name] = hex.EncodeToString(digest[:])
	}
	record := bootRecord{Manifest: b.Manifest, Plan: b.Plan, SourcePlan: b.SourcePlan}
	data, err := json.Marshal(record)
	if err != nil || len(data) > maxBootMetadata {
		return domain.ErrInvalid
	}
	floor, err := s.floor()
	if errors.Is(err, os.ErrNotExist) {
		// Once a checkpoint exists, a missing floor cannot reset known state.
		if _, e := os.Lstat(filepath.Join(s.root, "boot", "confirmed.json")); !errors.Is(e, os.ErrNotExist) {
			return domain.ErrUnavailable
		}
		floor = domain.SecurityFloor{Node: b.Manifest.Node, RecordedAt: b.Manifest.CreatedAt}
		fb, _ := json.Marshal(floor)
		err = atomicFile(filepath.Join(s.root, "boot"), "floor.json", fb)
	}
	if err != nil || floor.Node != b.Manifest.Node {
		return domain.ErrUnavailable
	}
	if _, err = s.Stage(ctx, runtime.Artifact{ID: id, Digest: id, Files: b.Files}); err != nil {
		return err
	}
	path := filepath.Join(s.root, "boot", "staged", id+".json")
	var old bootRecord
	if err := decodeBoot(path, &old); err == nil {
		record.Manifest.CreatedAt = old.Manifest.CreatedAt
		record.Plan.Runtime.Now = old.Plan.Runtime.Now
		canonical, _ := json.Marshal(record)
		previous, _ := json.Marshal(old)
		if !bytes.Equal(previous, canonical) {
			return domain.ErrConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicFile(filepath.Dir(path), filepath.Base(path), data)
}

func (s *Store) loadBootRecord(e runtime.BootEvidence) (runtime.BootBundle, error) {
	var b runtime.BootBundle
	if !e.Node.Valid() || !digestID.MatchString(e.ArtifactID) || e.VerifiedAt.IsZero() {
		return b, domain.ErrInvalid
	}
	var record bootRecord
	metadataPath := filepath.Join(s.root, "boot", "staged", e.ArtifactID+".json")
	data, err := secureRead(metadataPath, maxBootMetadata)
	if err != nil {
		return b, err
	}
	digest := sha256.Sum256(data)
	if !digestID.MatchString(e.MetadataDigest) || hex.EncodeToString(digest[:]) != e.MetadataDigest {
		return b, domain.ErrInvalid
	}
	if err := decodeBootBytes(data, &record); err != nil {
		return b, err
	}
	m := record.Manifest
	if m.Validate() != nil || len(m.FileDigests) == 0 || m.Node != e.Node || m.ArtifactID != e.ArtifactID || m.Version != e.Version || m.Generation != e.Generation || e.VerifiedAt.Before(m.CreatedAt) {
		return b, domain.ErrInvalid
	}
	base := filepath.Join(s.root, "releases", e.ArtifactID)
	files := map[string][]byte{}
	var size int64
	err = filepath.WalkDir(base, func(path string, entry stdfs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return secureInfo(path, true)
		}
		name, err := filepath.Rel(base, path)
		if err != nil || name == "." || strings.HasPrefix(name, "..") {
			return domain.ErrInvalid
		}
		want, ok := m.FileDigests[name]
		if !ok {
			return domain.ErrInvalid
		}
		data, err := secureRead(path, (64<<20)-size)
		if err != nil {
			return err
		}
		size += int64(len(data))
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != want {
			return domain.ErrInvalid
		}
		files[name] = data
		return nil
	})
	if err != nil {
		return b, err
	}
	id, err := artifactDigest(files)
	if err != nil || id != e.ArtifactID || len(files) != len(m.FileDigests) || len(files["nginx.conf"]) == 0 {
		return b, domain.ErrInvalid
	}
	return runtime.BootBundle{Manifest: m, Files: files, Plan: record.Plan, SourcePlan: record.SourcePlan, VerifiedAt: e.VerifiedAt}, nil
}

func (s *Store) Confirm(ctx context.Context, e runtime.BootEvidence) error {
	if !digestID.MatchString(e.ArtifactID) {
		return domain.ErrInvalid
	}
	unlock, err := s.bootLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	metadata, err := secureRead(filepath.Join(s.root, "boot", "staged", e.ArtifactID+".json"), maxBootMetadata)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(metadata)
	e.MetadataDigest = hex.EncodeToString(digest[:])
	b, err := s.loadBootRecord(e)
	if err != nil {
		return err
	}
	floor, err := s.floor()
	if err != nil || floor.Node != e.Node || e.VerifiedAt.Before(floor.RecordedAt) {
		return domain.ErrUnavailable
	}
	for _, id := range b.Manifest.MaterialIDs {
		if slices.Contains(floor.RevokedMaterialIDs, id) {
			return domain.ErrUnavailable
		}
	}
	var old bootCheckpoint
	path := filepath.Join(s.root, "boot", "confirmed.json")
	if err := decodeBoot(path, &old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if old.Current.ArtifactID != "" && old.Current.Node != e.Node {
		return domain.ErrConflict
	}
	if e.VerifiedAt.Before(checkpointVerifiedAt(old)) {
		return domain.ErrUnavailable
	}
	previous := old.Current
	if old.Current.ArtifactID == e.ArtifactID && old.Current.Generation == e.Generation {
		previous = old.Previous
	}
	// Advance safety independently before publishing the new configuration pointer.
	// A failed current artifact may only recover inputs matching this authority.
	if b.SourcePlan == nil {
		if floor.Sequence == ^uint64(0) {
			return domain.ErrUnavailable
		}
		if floor.AuthorizationID != "" {
			floor.Sequence++
		}
		floor.RecordedAt = e.VerifiedAt
		floor.AuthorizationID = b.Manifest.AuthorizationID
		next := maps.Clone(floor.SecurityBindings)
		if next == nil {
			next = map[string]string{}
		}
		for k, v := range safety.Bindings(b.Plan.Runtime) {
			next[k] = v
		}
		floor.SecurityBindings = next
		if old.Current.ArtifactID != "" {
			old.MinimumFloor = floor
			minimum, err := json.Marshal(old)
			if err != nil {
				return err
			}
			if err = atomicFile(filepath.Dir(path), filepath.Base(path), minimum); err != nil {
				return err
			}
		}
		encoded, err := json.Marshal(floor)
		if err != nil {
			return err
		}
		if err = atomicFile(filepath.Join(s.root, "boot"), "floor.json", encoded); err != nil {
			return err
		}
	}
	data, err := json.Marshal(bootCheckpoint{Current: e, Previous: previous, MinimumFloor: floor, ReceiptPending: true})
	if err != nil {
		return err
	}
	return atomicFile(filepath.Dir(path), filepath.Base(path), data)
}

// Both retained configurations contribute to the highest completed observation
// time, including when a corrupted current artifact requires a safe fallback.
func checkpointVerifiedAt(cp bootCheckpoint) time.Time {
	if cp.Previous.VerifiedAt.After(cp.Current.VerifiedAt) {
		return cp.Previous.VerifiedAt
	}
	return cp.Current.VerifiedAt
}

func floorCoversCheckpoint(floor domain.SecurityFloor, cp bootCheckpoint, node domain.NodeRef) bool {
	if floor.Node != node || cp.Current.Node != node || floor.Sequence < cp.MinimumFloor.Sequence || floor.RecordedAt.Before(cp.MinimumFloor.RecordedAt) {
		return false
	}
	if cp.MinimumFloor.AuthorizationID != "" && floor.AuthorizationID != cp.MinimumFloor.AuthorizationID {
		return false
	}
	for k, v := range cp.MinimumFloor.SecurityBindings {
		if floor.SecurityBindings[k] != v {
			return false
		}
	}
	for _, id := range cp.MinimumFloor.RevokedMaterialIDs {
		if !slices.Contains(floor.RevokedMaterialIDs, id) {
			return false
		}
	}
	return true
}

func (s *Store) LoadConfirmed(ctx context.Context, node domain.NodeRef) (out runtime.BootBundle, err error) {
	if !node.Valid() {
		return out, domain.ErrInvalid
	}
	unlock, err := s.bootLock(ctx)
	if err != nil {
		return out, err
	}
	defer unlock()
	var cp bootCheckpoint
	if err = decodeBoot(filepath.Join(s.root, "boot", "confirmed.json"), &cp); err != nil {
		return out, err
	}
	floor, err := s.floor()
	if err != nil || !floorCoversCheckpoint(floor, cp, node) {
		return out, domain.ErrUnavailable
	}
	for _, e := range []runtime.BootEvidence{cp.Current, cp.Previous} {
		if e.Node != node {
			continue
		}
		if out, err = s.loadBootRecord(e); err == nil {
			out.CurrentFloor = floor
			return out, nil
		}
	}
	return out, domain.ErrUnavailable
}

// ConfirmKnown records a successful restart of an already confirmed artifact.
// It cannot authorize a staged candidate or change any security constraint.
// A single checkpoint write avoids advancing floor.json after traffic is live.
func (s *Store) ConfirmKnown(ctx context.Context, manifest domain.BootManifest, expected domain.SecurityFloor, verifiedAt time.Time) error {
	if manifest.Validate() != nil || expected.Validate() != nil || verifiedAt.IsZero() {
		return domain.ErrInvalid
	}
	unlock, err := s.bootLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	var cp bootCheckpoint
	path := filepath.Join(s.root, "boot", "confirmed.json")
	if err = decodeBoot(path, &cp); err != nil {
		return err
	}
	floor, err := s.floor()
	if err != nil || !floorCoversCheckpoint(floor, cp, manifest.Node) {
		return domain.ErrUnavailable
	}
	if floor.Node != expected.Node || floor.Sequence != expected.Sequence || !floor.RecordedAt.Equal(expected.RecordedAt) || floor.AuthorizationID != expected.AuthorizationID || !maps.Equal(floor.SecurityBindings, expected.SecurityBindings) || !slices.Equal(floor.RevokedMaterialIDs, expected.RevokedMaterialIDs) {
		return domain.ErrConflict
	}
	if floor.AuthorizationID != manifest.AuthorizationID || verifiedAt.Before(floor.RecordedAt) || verifiedAt.Before(checkpointVerifiedAt(cp)) {
		return domain.ErrUnavailable
	}
	for _, id := range manifest.MaterialIDs {
		if slices.Contains(floor.RevokedMaterialIDs, id) {
			return domain.ErrUnavailable
		}
	}
	for _, known := range []runtime.BootEvidence{cp.Current, cp.Previous} {
		if known.Node != manifest.Node || known.ArtifactID != manifest.ArtifactID || known.Version != manifest.Version || known.Generation != manifest.Generation || verifiedAt.Before(known.VerifiedAt) {
			continue
		}
		// Keep the protected MetadataDigest from the existing evidence. A same
		// authorization string, version name, or new staged file is not proof.
		bundle, err := s.loadBootRecord(known)
		if err != nil || !reflect.DeepEqual(bundle.Manifest, manifest) {
			continue
		}
		previous := cp.Current
		if cp.Current.ArtifactID == known.ArtifactID && cp.Current.Generation == known.Generation {
			previous = cp.Previous
		}
		known.VerifiedAt = verifiedAt.UTC()
		data, err := json.Marshal(bootCheckpoint{Current: known, Previous: previous, MinimumFloor: floor, ReceiptPending: true})
		if err != nil {
			return err
		}
		return atomicFile(filepath.Dir(path), filepath.Base(path), data)
	}
	return domain.ErrUnavailable
}

func (s *Store) RaiseFloor(ctx context.Context, next domain.SecurityFloor) error {
	if next.Validate() != nil {
		return domain.ErrInvalid
	}
	unlock, err := s.bootLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	old, err := s.floor()
	if err != nil || next.Node != old.Node || next.Sequence < old.Sequence || next.RecordedAt.Before(old.RecordedAt) {
		return domain.ErrConflict
	}
	var checkpoint bootCheckpoint
	checkpointPath := filepath.Join(s.root, "boot", "confirmed.json")
	hasCheckpoint := false
	if err := decodeBoot(checkpointPath, &checkpoint); err == nil {
		hasCheckpoint = true
		minimum := checkpoint.MinimumFloor
		// A safe fallback may select an older artifact, but it cannot forget
		// the completed startup time recorded for either retained artifact.
		if next.RecordedAt.Before(checkpointVerifiedAt(checkpoint)) {
			return domain.ErrConflict
		}
		if checkpoint.Current.Node != next.Node || minimum.Node != next.Node || next.Sequence < minimum.Sequence || next.RecordedAt.Before(minimum.RecordedAt) {
			return domain.ErrConflict
		}
		for _, id := range minimum.RevokedMaterialIDs {
			if !slices.Contains(old.RevokedMaterialIDs, id) {
				old.RevokedMaterialIDs = append(old.RevokedMaterialIDs, id)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if next.AuthorizationID == "" {
		next.AuthorizationID = old.AuthorizationID
	}
	if next.SecurityBindings == nil {
		next.SecurityBindings = maps.Clone(old.SecurityBindings)
	}
	if next.AuthorizationID != old.AuthorizationID || !maps.Equal(next.SecurityBindings, old.SecurityBindings) {
		return domain.ErrConflict
	}
	ids := slices.Clone(old.RevokedMaterialIDs)
	for _, id := range next.RevokedMaterialIDs {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if len(ids) > 4096 || (next.Sequence == old.Sequence && (len(ids) != len(old.RevokedMaterialIDs) || !next.RecordedAt.Equal(old.RecordedAt))) {
		return domain.ErrConflict
	}
	next.RevokedMaterialIDs = ids
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	// Publish the required minimum first. A crash between these two atomic
	// writes fails closed; it cannot expose a newer receipt with an older floor.
	if hasCheckpoint {
		checkpoint.MinimumFloor = next
		cp, err := json.Marshal(checkpoint)
		if err != nil {
			return err
		}
		if err := atomicFile(filepath.Dir(checkpointPath), filepath.Base(checkpointPath), cp); err != nil {
			return err
		}
	}
	return atomicFile(filepath.Join(s.root, "boot"), "floor.json", data)
}
