// Package reports is a fixed local CLI-to-console sanitized receipt bridge.
package reports

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/backup/application"
	"io"
	"os"
	"path/filepath"
)

type Store struct{ Directory string }

const name = "latest-recovery-report.json"

func (s Store) Write(r application.SafeReport) error {
	if !r.Valid() || !filepath.IsAbs(s.Directory) || filepath.Clean(s.Directory) == "/" {
		return errors.New("invalid safe report")
	}
	if e := os.MkdirAll(s.Directory, 0700); e != nil {
		return e
	}
	root, e := os.OpenRoot(s.Directory)
	if e != nil {
		return e
	}
	defer root.Close()
	b, _ := json.Marshal(r)
	defer root.Remove(".recovery-report-" + r.ID)
	f, e := root.OpenFile(".recovery-report-"+r.ID, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return root.Rename(".recovery-report-"+r.ID, name)
}
func (s Store) Latest(ctx context.Context) (*application.SafeReport, error) {
	if s.Directory == "" {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	root, e := os.OpenRoot(s.Directory)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, errors.New("report unavailable")
	}
	defer root.Close()
	f, e := root.Open(name)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, errors.New("report unavailable")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	var r application.SafeReport
	var extra any
	if d.Decode(&r) != nil || d.Decode(&extra) != io.EOF || !r.Valid() {
		return nil, errors.New("report invalid")
	}
	return &r, nil
}
