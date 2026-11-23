// Package logfile reads only fixed access-log basenames beneath an opened volume.
package logfile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

var names = regexp.MustCompile(`^access(\.[0-9]{8}T[0-9]{6}\.[0-9]{9})?\.log$`)

type Source struct {
	nodeID, volumeID string
	root             *os.Root
	MaxBytes         int64
	MaxFiles         int
}

func Open(path string) (*Source, error) {
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, errors.New("log volume unavailable")
	}
	return &Source{root: r, MaxBytes: 1 << 30, MaxFiles: 2048}, nil
}
func (s *Source) Close() error { return s.root.Close() }
func (s *Source) open(name string) (*os.File, error) {
	if !names.MatchString(name) {
		return nil, domain.ErrInvalid
	}
	st, e := s.root.Lstat(name)
	if e != nil || !st.Mode().IsRegular() {
		return nil, domain.ErrInvalid
	}
	f, e := s.root.Open(name)
	if e != nil {
		return nil, e
	}
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		f.Close()
		return nil, domain.ErrSourceChanged
	}
	return f, nil
}
func identity(f *os.File, closed bool) (domain.Segment, error) {
	st, e := f.Stat()
	if e != nil {
		return domain.Segment{}, e
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return domain.Segment{}, domain.ErrInvalid
	}
	prefix := make([]byte, 256)
	n, e := f.ReadAt(prefix, 0)
	if e != nil && e != io.EOF {
		return domain.Segment{}, e
	}
	id := fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%d:%d", v.Dev, v.Ino)))
	if n == 0 {
		return domain.Segment{ID: id, Size: st.Size()}, nil
	}
	prefix = prefix[:n]
	if i := bytes.IndexByte(prefix, '\n'); i >= 0 {
		prefix = prefix[:i+1]
	} else if n < 256 && !closed {
		return domain.Segment{ID: id, Size: st.Size()}, nil
	}
	return domain.Segment{ID: id, Fingerprint: fmt.Sprintf("%x", sha256.Sum256(prefix)), Size: st.Size()}, nil
}
func (s *Source) Discover(ctx context.Context) ([]domain.Segment, error) {
	d, e := s.root.Open(".")
	if e != nil {
		return nil, e
	}
	defer d.Close()
	entries, e := d.ReadDir(s.MaxFiles + 1)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > s.MaxFiles {
		return nil, domain.ErrCapacity
	}
	out := []domain.Segment{}
	var size int64
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if !names.MatchString(entry.Name()) {
			continue
		}
		f, e := s.open(entry.Name())
		if e != nil {
			return nil, e
		}
		closed := false
		if entry.Name() != "access.log" {
			st, e := s.root.Lstat(entry.Name() + ".closed")
			closed = e == nil && st.Mode().IsRegular() && st.Size() == 0
		}
		v, e := s.identity(f, closed)
		f.Close()
		if errors.Is(e, io.ErrUnexpectedEOF) {
			continue
		}
		if e != nil {
			return nil, e
		}
		size += v.Size
		if size > s.MaxBytes {
			return nil, domain.ErrCapacity
		}
		v.Path = entry.Name()
		if strings.HasPrefix(v.Path, "access.") && v.Path != "access.log" {
			st, e := s.root.Lstat(v.Path + ".closed")
			v.Closed = e == nil && st.Mode().IsRegular() && st.Size() == 0
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
func anchor(f *os.File, end int64) (string, error) {
	if end == 0 {
		return "", nil
	}
	start := max(int64(0), end-256)
	b := make([]byte, end-start)
	if _, e := f.ReadAt(b, start); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}
func (s *Source) Read(ctx context.Context, seg domain.Segment, c domain.Cursor) (domain.Read, error) {
	f, e := s.open(seg.Path)
	if e != nil {
		return domain.Read{}, e
	}
	defer f.Close()
	actual, e := s.identity(f, seg.Closed)
	if e != nil {
		return domain.Read{}, e
	}
	if actual.ID != seg.ID || actual.Fingerprint != seg.Fingerprint || actual.Size < c.Offset || c.Fingerprint != "" && c.Fingerprint != actual.Fingerprint {
		return domain.Read{}, domain.ErrSourceChanged
	}
	previous, e := anchor(f, c.Offset)
	if e != nil || c.Anchor != "" && previous != c.Anchor {
		return domain.Read{}, domain.ErrSourceChanged
	}
	if _, e = f.Seek(c.Offset, io.SeekStart); e != nil {
		return domain.Read{}, e
	}
	end := min(actual.Size, c.Offset+domain.MaxRead)
	reader := bufio.NewReaderSize(io.LimitReader(f, end-c.Offset), domain.MaxLine+1)
	out := domain.Read{End: c.Offset, Dropping: c.Dropping}
	hash := sha256.New()
	pending := []byte{}
	for out.End < int64(end) && len(out.Events) < domain.MaxRows {
		if e = ctx.Err(); e != nil {
			return domain.Read{}, e
		}
		part, err := reader.ReadSlice('\n')
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return domain.Read{}, err
		}
		if len(part) == 0 {
			break
		}
		if out.Dropping {
			hash.Write(part)
			out.End += int64(len(part))
			if part[len(part)-1] == '\n' {
				out.Dropping = false
			}
			continue
		}
		if err == bufio.ErrBufferFull {
			out.Oversize++
			out.Dropping = true
			hash.Write(part)
			out.End += int64(len(part))
			continue
		}
		pending = part
		if part[len(part)-1] != '\n' {
			if !seg.Closed || end < actual.Size {
				break
			}
			out.Invalid++
		} else {
			event, reason := decode(part)
			switch reason {
			case "":
				event.NodeID = actual.NodeID
				out.Events = append(out.Events, event)
			case "schema":
				out.Schema++
			default:
				out.Invalid++
			}
		}
		hash.Write(pending)
		out.End += int64(len(pending))
	}
	after, e := f.Stat()
	if e != nil || after.Size() < actual.Size {
		return domain.Read{}, domain.ErrSourceChanged
	}
	out.Checksum = fmt.Sprintf("%x", hash.Sum(nil))
	out.Anchor, e = anchor(f, out.End)
	if e != nil {
		return domain.Read{}, e
	}
	return out, nil
}
