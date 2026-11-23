package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/deployment/application/bootstrap"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type DockerVolumes struct{}

func (DockerVolumes) Storage(ctx context.Context, path string) (app.StorageFacts, error) {
	if e := ctx.Err(); e != nil {
		return app.StorageFacts{}, e
	}
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path {
		return app.StorageFacts{}, app.ErrStorage
	}
	st, e := os.Lstat(path)
	if e != nil {
		return app.StorageFacts{}, e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return app.StorageFacts{}, app.ErrStorage
	}
	return app.StorageFacts{Directory: st.IsDir(), UID: stat.Uid, Mode: uint32(st.Mode().Perm()), Device: uint64(stat.Dev)}, nil
}

type boundedVolumeOutput struct{ bytes.Buffer }

func (b *boundedVolumeOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, app.ErrStorage
	}
	return b.Buffer.Write(p)
}
func volumeCommand(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out boundedVolumeOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return nil, errors.New("volume operation unavailable or result uncertain; inspect before retry")
	}
	return out.Bytes(), nil
}
func (DockerVolumes) Volumes(ctx context.Context, prefix string) ([]app.Volume, error) {
	raw, e := volumeCommand(ctx, "volume", "ls", "--filter", "name=^"+prefix+"-", "--format", "{{json .}}")
	if e != nil {
		return nil, e
	}
	names := []string{}
	d := json.NewDecoder(bytes.NewReader(raw))
	for d.More() {
		var row struct{ Name string }
		if e = d.Decode(&row); e != nil || len(names) >= 64 {
			return nil, app.ErrStorage
		}
		if strings.HasPrefix(row.Name, prefix+"-") {
			names = append(names, row.Name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	args := append([]string{"volume", "inspect"}, names...)
	raw, e = volumeCommand(ctx, args...)
	if e != nil {
		return nil, e
	}
	var rows []struct {
		Name, Driver string
		Labels       map[string]string
		Options      map[string]string
	}
	if json.Unmarshal(raw, &rows) != nil {
		return nil, app.ErrStorage
	}
	out := []app.Volume{}
	for _, r := range rows {
		var v app.Volume
		v.Name = r.Name
		v.Path = r.Options["device"]
		v.Class = r.Labels["gatebeam.volume_class"]
		v.Node.ID = r.Labels["gatebeam.node_id"]
		v.Node.Epoch, _ = strconv.ParseUint(r.Labels["gatebeam.node_epoch"], 10, 64)
		v.Bind = r.Driver == "local" && r.Options["type"] == "none" && r.Options["o"] == "bind"
		out = append(out, v)
	}
	return out, nil
}
func (DockerVolumes) Create(ctx context.Context, v app.Volume) error {
	_, e := volumeCommand(ctx, "volume", "create", "--driver", "local", "--label", "gatebeam.node_id="+v.Node.ID, "--label", "gatebeam.node_epoch="+strconv.FormatUint(v.Node.Epoch, 10), "--label", "gatebeam.volume_class="+v.Class, "--opt", "type=none", "--opt", "o=bind", "--opt", "device="+v.Path, v.Name)
	return e
}
