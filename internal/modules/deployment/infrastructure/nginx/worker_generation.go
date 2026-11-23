package nginx

import (
	"errors"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"os"
	"strconv"
	"strings"
)

// Linux edge images expose direct child PIDs. A matching old worker response
// cannot acknowledge a HUP: at least one worker spawned after the signal must
// exist before the new-connection version probe may succeed.
func (p *Process) workers() (map[string]bool, error) {
	if !p.running() {
		return nil, edge.ErrNotRunning
	}
	id := strconv.Itoa(p.cmd.Process.Pid)
	b, e := p.proc.ReadFile("/proc/" + id + "/task/" + id + "/children")
	if e != nil {
		return nil, errors.New("Nginx worker generation unavailable")
	}
	out := map[string]bool{}
	for _, id := range strings.Fields(string(b)) {
		out[id] = true
	}
	return out, nil
}

// Old workers may keep streaming connections while retiring. Wait only for
// their listening sockets to close, never for their long-lived requests to end.
func (p *Process) retiredListeners(previous map[string]bool) (bool, error) {
	if len(previous) == 0 {
		return true, nil
	}
	unknown := errors.New("Nginx listener observation unavailable")
	listeners := map[string]bool{}
	// Supported edge images expose both protocol tables. A missing table is
	// unknown observation, not evidence that its listeners have disappeared.
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, e := p.proc.ReadFile(file)
		if e != nil {
			return false, unknown
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		header := strings.Fields(lines[0])
		if len(header) < 4 || header[0] != "sl" || header[3] != "st" {
			return false, unknown
		}
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			if len(f) < 10 {
				return false, unknown
			}
			state, e := strconv.ParseUint(f[3], 16, 8)
			if e != nil {
				return false, unknown
			}
			if state == 10 {
				inode, e := strconv.ParseUint(f[9], 10, 64)
				if e != nil || inode == 0 {
					return false, unknown
				}
				listeners["socket:["+f[9]+"]"] = true
			}
		}
	}
	for pid := range previous {
		dir := "/proc/" + pid + "/fd"
		entries, e := p.proc.ReadDir(dir)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				if _, gone := p.proc.Lstat("/proc/" + pid); errors.Is(gone, os.ErrNotExist) {
					continue
				}
			}
			return false, unknown
		}
		for _, entry := range entries {
			path := dir + "/" + entry.Name()
			target, e := p.proc.Readlink(path)
			if e != nil {
				// Only a separately confirmed disappeared descriptor is a benign close
				// race. Permissions/I/O errors or an extant descriptor remain unknown.
				if errors.Is(e, os.ErrNotExist) {
					if _, gone := p.proc.Lstat(path); errors.Is(gone, os.ErrNotExist) {
						continue
					}
				}
				return false, unknown
			}
			if listeners[target] {
				return false, nil
			}
		}
	}
	return true, nil
}

// procReader isolates the Linux process-observation boundary for error testing.
type procReader interface {
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]os.DirEntry, error)
	Readlink(string) (string, error)
	Lstat(string) (os.FileInfo, error)
}
type nativeProc struct{}

func (nativeProc) ReadFile(path string) ([]byte, error)       { return os.ReadFile(path) }
func (nativeProc) ReadDir(path string) ([]os.DirEntry, error) { return os.ReadDir(path) }
func (nativeProc) Readlink(path string) (string, error)       { return os.Readlink(path) }
func (nativeProc) Lstat(path string) (os.FileInfo, error)     { return os.Lstat(path) }
