// Package parquet owns durable local, immutable compressed log objects.
package parquet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	pq "github.com/parquet-go/parquet-go"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

type Row struct {
	NodeID          string `parquet:"node_id"`
	RateRequest     string `parquet:"rate_req"`
	RateConnection  string `parquet:"rate_conn"`
	PathPattern     string `parquet:"path_pattern"`
	ConfigID        string `parquet:"config_id"`
	TargetID        string `parquet:"target_id"`
	UpstreamOutcome string `parquet:"upstream_outcome"`
	SiteID          string `parquet:"site_id"`
	RequestID       string `parquet:"request_id"`
	Route           string `parquet:"route"`
	Method          string `parquet:"method"`
	Time            int64  `parquet:"time,timestamp(microsecond)"`
	Status          int32  `parquet:"status"`
	Bytes           int64  `parquet:"bytes_sent"`
	Micros          int64  `parquet:"request_micros"`
}

var batchID = regexp.MustCompile(`^[0-9a-f]{64}(-[0-9]{1,20}-[0-9]{1,20})?$`)

type Writer struct {
	nodeID   string
	root     string
	mu       sync.Mutex
	MaxBytes int64
	MaxFiles int
}

func New(path string) (*Writer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return nil, domain.ErrInvalid
	}
	path = filepath.Clean(path)
	if e := os.MkdirAll(path, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, domain.ErrInvalid
	}
	parent, e := os.Open(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	e = parent.Sync()
	parent.Close()
	if e != nil {
		return nil, e
	}
	return &Writer{root: path, MaxBytes: 1 << 30, MaxFiles: 16384}, nil
}

// The spool layout is root/site/date/hour/object. Directory reads are paged
// before allocation, and every subtree shares the same remaining budgets.
const spoolScanPage = 64
const spoolMaxDepth = 4

type spoolDirectory interface {
	ReadDir(int) ([]os.DirEntry, error)
	Close() error
}

func (w *Writer) capacity(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	// Validate before subtraction so invalid caller-supplied budgets cannot wrap.
	reserve := 4*domain.MaxRows + 1
	if w.nodeID != "" {
		reserve = 5*domain.MaxRows + 1
	}
	if w.MaxFiles <= reserve || w.MaxBytes < 16*domain.MaxRead {
		return domain.ErrCapacity
	}
	return scanCapacity(ctx, w.root, w.MaxFiles-reserve, w.MaxBytes-16*domain.MaxRead, func(path string) (spoolDirectory, error) { return os.Open(path) })
}
func scanCapacity(ctx context.Context, root string, maxEntries int, maxBytes int64, open func(string) (spoolDirectory, error)) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if maxEntries < 1 || maxBytes < 0 {
		return domain.ErrCapacity
	}
	remainingEntries, remainingBytes := maxEntries-1, maxBytes // include the root
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		directory, e := open(path)
		if e != nil {
			return e
		}
		defer directory.Close()
		for {
			if e := ctx.Err(); e != nil {
				return e
			}
			// At most one look-ahead entry is needed to reject an exhausted budget.
			entries, err := directory.ReadDir(min(spoolScanPage, remainingEntries+1))
			if e := ctx.Err(); e != nil {
				return e
			}
			if err != nil && err != io.EOF {
				return err
			}
			// Charge the entire returned page before descending so pending
			// parent entries cannot leave uncharged budget for child reads.
			if len(entries) > remainingEntries {
				return domain.ErrCapacity
			}
			remainingEntries -= len(entries)
			for _, entry := range entries {
				if e := ctx.Err(); e != nil {
					return e
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return domain.ErrInvalid
				}
				if entry.IsDir() {
					if depth >= spoolMaxDepth || depth == 3 && !domain.ValidSite(entry.Name()) {
						return domain.ErrCapacity
					}
					if e := visit(filepath.Join(path, entry.Name()), depth+1); e != nil {
						return e
					}
				} else {
					info, e := entry.Info()
					if e != nil {
						return e
					}
					if !info.Mode().IsRegular() {
						return domain.ErrInvalid
					}
					if info.Size() < 0 || info.Size() > remainingBytes {
						return domain.ErrCapacity
					}
					remainingBytes -= info.Size()
				}
			}
			if err == io.EOF {
				return nil
			}
		}
	}
	return visit(root, 0)
}
func (w *Writer) Persist(ctx context.Context, id string, events []domain.Event) ([]domain.Object, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !batchID.MatchString(id) || len(events) > domain.MaxRows {
		return nil, domain.ErrInvalid
	}
	if e := w.capacity(ctx); e != nil {
		return nil, e
	}
	groups := map[string][]domain.Event{}
	for _, e := range events {
		if !domain.ValidSite(e.SiteID) || e.Time.Year() < 2020 || e.Time.Year() > 2100 {
			return nil, domain.ErrInvalid
		}
		key := e.SiteID + "/" + e.Time.UTC().Format("2006-01-02/15")
		if w.nodeID != "" {
			if e.NodeID != w.nodeID {
				return nil, domain.ErrSourceChanged
			}
			key += "/" + w.nodeID
		}
		groups[key] = append(groups[key], e)
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	objects := []domain.Object{}
	for _, partition := range keys {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		list := groups[partition]
		rows := make([]Row, len(list))
		minTime, maxTime := list[0].Time, list[0].Time
		for i, v := range list {
			rows[i] = Row{v.NodeID, v.RateRequest, v.RateConnection, v.PathPattern, v.ConfigID, v.TargetID, v.UpstreamOutcome, v.SiteID, v.RequestID, v.Route, v.Method, v.Time.UnixMicro(), int32(v.Status), v.Bytes, v.Micros}
			if v.Time.Before(minTime) {
				minTime = v.Time
			}
			if v.Time.After(maxTime) {
				maxTime = v.Time
			}
		}
		key := partition + "/" + id + ".parquet"
		path := filepath.Join(w.root, filepath.FromSlash(key))
		dir := filepath.Dir(path)
		if e := os.MkdirAll(dir, 0700); e != nil {
			return nil, e
		}
		f, e := os.CreateTemp(dir, ".pending-")
		if e != nil {
			return nil, e
		}
		tmp := f.Name()
		_ = f.Chmod(0600)
		schemaVersion := 1
		if w.nodeID != "" {
			schemaVersion = 2
		}
		writer := pq.NewGenericWriter[Row](f, pq.Compression(&pq.Snappy), pq.MaxRowsPerRowGroup(domain.MaxRows), pq.KeyValueMetadata("schema_version", fmt.Sprint(schemaVersion)))
		_, e = writer.Write(rows)
		if e == nil {
			e = writer.Close()
		}
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			os.Remove(tmp)
			return nil, e
		}
		// Link publishes without overwriting a previously committed object. A
		// replay must be byte-identical; conflicting source content fails closed.
		if e = os.Link(tmp, path); errors.Is(e, os.ErrExist) {
			digest := func(name string) (string, error) {
				f, e := os.Open(name)
				if e != nil {
					return "", e
				}
				defer f.Close()
				h := sha256.New()
				_, e = io.Copy(h, f)
				return fmt.Sprintf("%x", h.Sum(nil)), e
			}
			want, err := digest(tmp)
			if err != nil {
				os.Remove(tmp)
				return nil, err
			}
			actual, err := digest(path)
			if err != nil || want != actual {
				os.Remove(tmp)
				return nil, domain.ErrSourceChanged
			}
		} else if e != nil {
			os.Remove(tmp)
			return nil, e
		}
		if e = os.Remove(tmp); e != nil {
			return nil, e
		}
		for p := dir; ; p = filepath.Dir(p) {
			d, e := os.Open(p)
			if e != nil {
				return nil, e
			}
			e = d.Sync()
			d.Close()
			if e != nil {
				return nil, e
			}
			if p == w.root {
				break
			}
			if p == filepath.Dir(p) {
				return nil, domain.ErrInvalid
			}
		}
		f, e = os.Open(path)
		if e != nil {
			return nil, e
		}
		h := sha256.New()
		n, e := io.Copy(h, f)
		f.Close()
		if e != nil {
			return nil, e
		}
		objects = append(objects, domain.Object{NodeID: w.nodeID, SchemaVersion: schemaVersion, Key: key, Checksum: fmt.Sprintf("%x", h.Sum(nil)), SiteID: list[0].SiteID, Hour: list[0].Time.UTC().Format("2006-01-02/15"), Rows: int64(len(rows)), Bytes: n, MinTime: minTime, MaxTime: maxTime})
	}
	return objects, nil
}

// NewNode writes only schema2 objects into a node-qualified namespace. New is
// retained for the controlled legacy bridge until its original logs migrate.
func NewNode(path, nodeID string) (*Writer, error) {
	if !domain.ValidSite(nodeID) || nodeID == "00000000-0000-0000-0000-000000000000" {
		return nil, domain.ErrInvalid
	}
	writer, e := New(path)
	if e != nil {
		return nil, e
	}
	writer.nodeID = nodeID
	return writer, nil
}
