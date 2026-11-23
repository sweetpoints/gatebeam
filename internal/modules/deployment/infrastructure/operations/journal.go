package operations

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type HostJournal struct {
	Directory string
	Runner    CommandRunner
}
type hostRecord struct {
	Step         upgrade.Step
	State        string
	IntentDigest string
}

func (j HostJournal) root() error {
	resolved, e := filepath.EvalSymlinks(j.Directory)
	if e != nil || resolved != j.Directory {
		return ErrOperation
	}
	st, e := os.Stat(j.Directory)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return ErrOperation
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return ErrOperation
	}
	return nil
}
func (j HostJournal) read(id string) (hostRecord, error) {
	var r hostRecord
	if !stepID.MatchString(id) || j.root() != nil {
		return r, ErrOperation
	}
	path := filepath.Join(j.Directory, id+".json")
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 256<<10 {
		return r, ErrOperation
	}
	f, e := os.Open(path)
	if e != nil {
		return r, ErrOperation
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		return r, ErrOperation
	}
	b, e := io.ReadAll(io.LimitReader(f, 256<<10+1))
	if e != nil || json.Unmarshal(b, &r) != nil || r.Step.ID != id || r.IntentDigest != IntentDigest(r.Step) {
		return r, ErrOperation
	}
	return r, nil
}
func syncHostDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (j HostJournal) write(r hostRecord, first bool) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	path := filepath.Join(j.Directory, r.Step.ID+".json")
	if first {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrOperation
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
		return syncHostDir(j.Directory)
	}
	f, e := os.CreateTemp(j.Directory, ".receipt-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return syncHostDir(j.Directory)
}
func (j HostJournal) Dispatch(ctx context.Context, s upgrade.Step) error {
	if !stepID.MatchString(s.ID) || j.root() != nil {
		return ErrOperation
	}
	if e := j.write(hostRecord{Step: s, State: "intent", IntentDigest: IntentDigest(s)}, true); e != nil {
		return e
	}
	runner := j.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	_, e := runner.Run(ctx, "systemd-run", "--unit=gatebeam-upgrade-"+s.ID, "--property=RuntimeMaxSec=600", "--property=RemainAfterExit=yes", "--property=Restart=no", "--service-type=exec", "--no-block", "/usr/local/bin/gatebeam-deploy-host", "--execute", s.ID)
	return e // No retry even if systemd accepted the unit before transport failure.
}
func (j HostJournal) Execute(ctx context.Context, id string, action func(context.Context, upgrade.Step) error) error {
	if j.root() != nil || !stepID.MatchString(id) {
		return ErrOperation
	}
	fd, e := syscall.Open(filepath.Join(j.Directory, id+".lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrOperation
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return ErrOperation
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	r, e := j.read(id)
	if e != nil || r.State != "intent" {
		return ErrOperation
	}
	r.State = "running"
	if e = j.write(r, false); e != nil {
		return e
	}
	e = action(ctx, r.Step)
	if e != nil {
		r.State = "unknown"
		if r.Step.Kind == "verify-api" {
			r.State = "failed"
		}
	} else {
		r.State = "succeeded"
	}
	return errors.Join(e, j.write(r, false))
}
func (j HostJournal) Receipt(id string) (HostReceipt, error) {
	r, e := j.read(id)
	return HostReceipt{StepID: r.Step.ID, State: r.State, IntentDigest: r.IntentDigest}, e
}
