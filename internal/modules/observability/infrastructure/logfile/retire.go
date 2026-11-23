package logfile

import (
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"os"
)

// RemoveRetired accepts only the exact closed identity approved by the owner.
// Missing-source recovery still removes its marker and syncs the directory;
// neither success nor a previous unlink substitutes for that durability barrier.
func (s *Source) RemoveRetired(seg domain.Segment) error {
	return s.removeRetired(seg, s.syncRetirementDirectory)
}
func (s *Source) removeRetired(seg domain.Segment, syncDirectory func() error) error {
	if !seg.Closed || seg.Path == "access.log" || !names.MatchString(seg.Path) {
		return domain.ErrInvalid
	}
	f, e := s.open(seg.Path)
	if e != nil {
		if _, err := s.root.Lstat(seg.Path); errors.Is(err, os.ErrNotExist) {
			return s.finishMissingRetirement(seg.Path, syncDirectory)
		}
		return e
	}
	defer f.Close()
	actual, e := s.identity(f, true)
	if e != nil {
		return e
	}
	// A reused basename belongs to its replacement. Preserve both replacement
	// source and marker, but still establish a directory barrier for the old intent.
	if actual.ID != seg.ID || actual.Fingerprint != seg.Fingerprint {
		return syncDirectory()
	}
	if actual.Size != seg.Size {
		return domain.ErrSourceChanged
	}
	marker, e := s.root.Lstat(seg.Path + ".closed")
	if e != nil {
		return e
	}
	if !marker.Mode().IsRegular() || marker.Size() != 0 {
		return domain.ErrSourceChanged
	}
	st, e := s.root.Lstat(seg.Path)
	if e != nil {
		return e
	}
	opened, e := f.Stat()
	if e != nil {
		return e
	}
	if !os.SameFile(st, opened) {
		return domain.ErrSourceChanged
	}
	if e = s.root.Remove(seg.Path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return s.finishMissingRetirement(seg.Path, syncDirectory)
}
func (s *Source) finishMissingRetirement(name string, syncDirectory func() error) error {
	// Recheck before touching the marker: a replacement path must never lose its
	// close proof. Only the supervisor mutates these controlled rotation names.
	if _, e := s.root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
		if e != nil {
			return e
		}
		return domain.ErrSourceChanged
	}
	marker, e := s.root.Lstat(name + ".closed")
	if e == nil {
		if !marker.Mode().IsRegular() || marker.Size() != 0 {
			return domain.ErrSourceChanged
		}
		if e = s.root.Remove(name + ".closed"); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return syncDirectory()
}
func (s *Source) syncRetirementDirectory() error {
	d, e := s.root.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
