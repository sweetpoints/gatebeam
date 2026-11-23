// Package duckdb runs only service-generated queries in a bounded private process.
package duckdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrUnavailable = errors.New("query_unavailable")
var ErrBusy = domain.ErrQueryBusy
var ErrTimeout = domain.ErrQueryTimeout

const Version = "v2.0.0"

type Config struct {
	LocalRoot                                                                   string
	Binary, Extension, TempRoot, Endpoint, Bucket, Region, AccessKey, SecretKey string
	Timeout                                                                     time.Duration
}
type Engine struct {
	cfg  Config
	slot chan struct{}
}

func New(c Config) (*Engine, error) {
	if !filepath.IsAbs(c.Binary) || !filepath.IsAbs(c.Extension) || !filepath.IsAbs(c.TempRoot) {
		return nil, domain.ErrInvalid
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, domain.ErrInvalid
	}
	if c.Timeout <= 0 || c.Timeout > 60*time.Second {
		c.Timeout = 60 * time.Second
	}
	if e = os.MkdirAll(c.TempRoot, 0700); e != nil {
		return nil, ErrUnavailable
	}
	info, e := os.Lstat(c.TempRoot)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Clean(c.TempRoot) == "/" {
		return nil, domain.ErrInvalid
	}
	directory, e := os.Open(c.TempRoot)
	if e != nil {
		return nil, ErrUnavailable
	}
	entries, e := directory.ReadDir(65)
	directory.Close()
	if e != nil && e != io.EOF {
		return nil, ErrUnavailable
	}
	// One executor owns this dedicated directory. Clean at most 64 previous
	// crash jobs before accepting new work; tmpfs is the physical byte bound.
	for _, entry := range entries[:min(len(entries), 64)] {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "query-") {
			if e = os.RemoveAll(filepath.Join(c.TempRoot, entry.Name())); e != nil {
				return nil, ErrUnavailable
			}
		}
	}
	if len(entries) > 64 {
		return nil, domain.ErrCapacity
	}
	return &Engine{cfg: c, slot: make(chan struct{}, 1)}, nil
}
func (e *Engine) TempRoot() string { return e.cfg.TempRoot }
func literal(s string) string      { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.context.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(p)
}

type cappedBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	cap      int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > b.cap-b.b.Len() {
		b.overflow = true
		return 0, errors.New("output_limit")
	}
	return b.b.Write(p)
}
func (e *Engine) Execute(ctx context.Context, f domain.QueryFilter, objects []domain.Object) ([]domain.QueryRow, error) {
	started := time.Now()
	if err := domain.ValidateObjects(f, objects); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrTimeout
	}
	select {
	case e.slot <- struct{}{}:
		defer func() { <-e.slot }()
	default:
		return nil, ErrBusy
	}
	if len(objects) == 0 {
		return []domain.QueryRow{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	dir, err := os.MkdirTemp(e.cfg.TempRoot, "query-")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer os.RemoveAll(dir)
	u, _ := url.Parse(e.cfg.Endpoint)
	var sql strings.Builder
	sql.WriteString(".output stderr\n.print GATEBEAM_QUERY_PHASE=configuration\n.output /dev/null\n")
	// Credentials travel through the private stdin pipe only. Neither SQL nor CLI
	// stderr is logged or returned, even on startup/parser failures.
	sql.WriteString("SET autoinstall_known_extensions=false; SET autoload_known_extensions=false; SET allow_community_extensions=false;\n.output stderr\n.print GATEBEAM_QUERY_PHASE=extension\n.output /dev/null\n")
	// Local Parquet support is built into the pinned CLI. Only remote reads
	// require httpfs and an S3 secret; keep them out of local query startup.
	if f.Source != "local" {
		fmt.Fprintf(&sql, "LOAD %s;\n", literal(e.cfg.Extension))
	}
	sql.WriteString(".output stderr\n.print GATEBEAM_QUERY_PHASE=settings\n.output /dev/null\n")
	fmt.Fprintf(&sql, "SET memory_limit='320MiB'; SET threads=1; SET max_temp_directory_size='900MiB'; SET temp_directory=%s; SET enable_progress_bar=false; SET enable_logging=false; SET TimeZone='UTC';\n", literal(filepath.Join(dir, "spill")))
	if f.Source != "local" {
		fmt.Fprintf(&sql, "CREATE SECRET history (TYPE s3, PROVIDER config, KEY_ID %s, SECRET %s, REGION %s, ENDPOINT %s, URL_STYLE 'path', USE_SSL %t, SCOPE %s);\n", literal(e.cfg.AccessKey), literal(e.cfg.SecretKey), literal(e.cfg.Region), literal(u.Host), u.Scheme == "https", literal("s3://"+e.cfg.Bucket+"/logs/"))
	}
	sql.WriteString(".output stderr\n.print GATEBEAM_QUERY_PHASE=query\n.output\n")
	uris := []string{}

	localFiles := []*os.File{}
	defer func() {
		for _, file := range localFiles {
			file.Close()
		}
	}()
	for _, o := range objects {
		if f.Source != "local" {
			uris = append(uris, literal("s3://"+e.cfg.Bucket+"/logs/"+o.Key))
			continue
		}
		if !filepath.IsAbs(e.cfg.LocalRoot) {
			return nil, ErrUnavailable
		}
		root, err := os.OpenRoot(e.cfg.LocalRoot)
		if err != nil {
			return nil, ErrUnavailable
		}
		src, err := root.Open(o.Key)
		root.Close()
		if err != nil {
			return nil, ErrUnavailable
		}
		localFiles = append(localFiles, src)
		info, err := src.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != o.Bytes {
			return nil, ErrUnavailable
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(contextReader{ctx, src}, o.Bytes+1))
		if err != nil || n != o.Bytes || hex.EncodeToString(h.Sum(nil)) != o.Checksum {
			return nil, ErrUnavailable
		}
		if _, err = src.Seek(0, io.SeekStart); err != nil {
			return nil, ErrUnavailable
		}
		// Open verified immutable inodes survive unlink. The active owner lease pins
		// producer cleanup; only these inherited descriptors enter fixed DuckDB SQL.
		// No scan-byte copy is charged to the query-worker's bounded memory/tmpfs.
		uris = append(uris, literal(fmt.Sprintf("/dev/fd/%d", 2+len(localFiles))))
	}

	// Bind source attribution to the authorized immutable object snapshot. Old
	// Parquet files need no new column and cannot self-assert another node.
	var provenance strings.Builder
	provenance.WriteString("CASE filename")
	for i, o := range objects {
		node := o.NodeID
		if node == "" {
			node = "legacy"
		}
		fmt.Fprintf(&provenance, " WHEN %s THEN %s", uris[i], literal(node))
	}
	provenance.WriteString(" ELSE 'legacy' END AS node_id")
	sites := []string{}
	for _, s := range f.SiteIDs {
		sites = append(sites, literal(s))
	}
	fmt.Fprintf(&sql, "SELECT strftime(time,'%%Y-%%m-%%dT%%H:%%M:%%S.%%fZ') AS time,%s,site_id,request_id,route,method,status,bytes_sent,request_micros,config_id FROM read_parquet([%s],hive_partitioning=false,union_by_name=true,filename=true) WHERE site_id IN (%s) AND time >= TIMESTAMP %s AND time < TIMESTAMP %s", provenance.String(), strings.Join(uris, ","), strings.Join(sites, ","), literal(f.From.UTC().Format("2006-01-02 15:04:05.999999")), literal(f.To.UTC().Format("2006-01-02 15:04:05.999999")))
	for _, p := range [][2]string{{"route", f.Route}, {"method", f.Method}, {"config_id", f.ConfigID}} {
		if p[1] != "" {
			fmt.Fprintf(&sql, " AND %s=%s", p[0], literal(p[1]))
		}
	}
	if f.Status != 0 {
		fmt.Fprintf(&sql, " AND status=%d", f.Status)
	}
	fmt.Fprintf(&sql, " ORDER BY time,site_id,request_id LIMIT %d;\n", domain.MaxQueryRows+1)
	cmd := exec.CommandContext(ctx, e.cfg.Binary, "-no-agent", "-no-init", "-batch", "-bail", "-json", ":memory:")
	cmd.ExtraFiles = localFiles
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/bin:/bin"}
	cmd.Stdin = strings.NewReader(sql.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	stdout := &cappedBuffer{cap: 8 << 20}
	cmd.Stdout = stdout
	childStarted := time.Now()
	phases := &queryPhases{started: childStarted}
	cmd.Stderr = phases
	prepareElapsed := childStarted.Sub(started)
	err = cmd.Run()
	if err != nil || ctx.Err() != nil {
		// Fixed numeric timings only: never expose generated SQL, credentials,
		// object keys, paths, or the child process stderr.
		fmt.Fprintf(os.Stderr, "gatebeam query child failure prepare_ms=%d child_ms=%d deadline_expired=%t context_cancelled=%t\n", prepareElapsed.Milliseconds(), time.Since(childStarted).Milliseconds(), errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(ctx.Err(), context.Canceled))
		phase, phaseMS, cliMS, loadedMS, queryMS := phases.observation(time.Now())
		fmt.Fprintf(os.Stderr, "gatebeam query phase failure phase=%s phase_ms=%d cli_ms=%d extension_loaded_ms=%d query_started_ms=%d\n", phase, phaseMS, cliMS, loadedMS, queryMS)
	}
	if ctx.Err() != nil {
		return nil, ErrTimeout
	}
	if stdout.overflow {
		return nil, domain.ErrCapacity
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	var rows []domain.QueryRow
	if json.Unmarshal(stdout.b.Bytes(), &rows) != nil {
		return nil, ErrUnavailable
	}
	if len(rows) > domain.MaxQueryRows {
		return nil, domain.ErrCapacity
	}
	return rows, nil
}
