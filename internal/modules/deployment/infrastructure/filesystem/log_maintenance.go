package filesystem

import (
	"context"
	"encoding/json"
	"errors"
	runtime "gatebeam/internal/modules/deployment/application/runtime"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var localLogName = regexp.MustCompile(`^(access|error)(\.[0-9]{8}T[0-9]{6}\.[0-9]{9})?\.log$`)

func (s *Store) InspectLogs(ctx context.Context, maxFiles int) (out runtime.LogUsage, err error) {
	dir, e := os.Open(filepath.Join(s.root, "logs"))
	if e != nil {
		return out, e
	}
	defer dir.Close()
	entries, e := dir.ReadDir(2*maxFiles + 5)
	if e != nil && e != io.EOF {
		return out, e
	}
	if len(entries) > 2*maxFiles+4 {
		return out, runtime.ErrLogCapacity
	}
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		if !localLogName.MatchString(entry.Name()) {
			continue
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return out, errors.New("unsafe local log file")
		}
		if info.Size() < 0 || out.Bytes > 1<<60-info.Size() {
			return out, runtime.ErrLogCapacity
		}
		out.Bytes += info.Size()
		out.Files++
		if entry.Name() == "access.log" || entry.Name() == "error.log" {
			out.ActiveBytes += info.Size()
		}
	}
	return out, nil
}
func (s *Store) LogWatermark(ctx context.Context) (out runtime.LogWatermark, err error) {
	if e := ctx.Err(); e != nil {
		return out, e
	}
	path := filepath.Join(s.root, "log-maintenance.json")
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return out, errors.New("invalid local log watermark")
	}
	file, e := os.Open(path)
	if e != nil {
		return out, e
	}
	defer file.Close()
	actual, e := file.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return out, errors.New("changed local log watermark")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&out); e != nil {
		return out, e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return out, errors.New("invalid local log watermark")
	}
	return out, nil
}
func (s *Store) SaveLogWatermark(ctx context.Context, value runtime.LogWatermark) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	body, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return atomicFile(s.root, "log-maintenance.json", body)
}
