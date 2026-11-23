package operations

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func writeHostFile(path string, b []byte, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if exclusive {
		flags |= os.O_EXCL
	}
	f, e := os.OpenFile(path, flags, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close(), syncHostDir(filepath.Dir(path)))
}
func replaceHostFile(path string, b []byte) error {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return ErrOperation
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrOperation
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".upgrade-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	e = f.Chmod(st.Mode().Perm())
	if e == nil && os.Geteuid() == 0 {
		e = f.Chown(int(owner.Uid), int(owner.Gid))
	}
	if e == nil {
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
	return syncHostDir(filepath.Dir(path))
}
