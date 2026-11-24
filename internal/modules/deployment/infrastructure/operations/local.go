package operations

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	provisioning "gatebeam/internal/modules/deployment/application/bootstrap"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	storageinfra "gatebeam/internal/modules/deployment/infrastructure/bootstrap"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// VerificationTimeout bounds production readiness, TLS and functional canaries after an upgrade.
const VerificationTimeout = 30 * time.Second

// HealthRequestTimeout bounds each private role status observation.
const HealthRequestTimeout = 2 * time.Second

type HostConfiguration struct {
	Node        domain.NodeDeployment `json:"node"`
	StorageRoot string                `json:"storage_root"`
}
type LocalHost struct {
	Configuration              HostConfiguration
	ConfigurationFile, Journal string
	Runner                     CommandRunner
}

func (h LocalHost) command(ctx context.Context, args ...string) ([]byte, error) {
	r := h.Runner
	if r == nil {
		r = ExecRunner{}
	}
	return r.Run(ctx, "docker", args...)
}
func (h LocalHost) compose(ctx context.Context, args ...string) ([]byte, error) {
	n := h.Configuration.Node
	return h.command(ctx, append([]string{"compose", "--env-file", n.EnvironmentFile, "-p", n.StoragePrefix, "-f", n.ComposeFile}, args...)...)
}
func (h LocalHost) snapshot(ctx context.Context, role string) (lifecycle.Snapshot, error) {
	var out lifecycle.Snapshot
	r, ok := h.Configuration.Node.Roles[role]
	if !ok {
		return out, ErrOperation
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(h.Configuration.Node.PrivateAddress, fmt.Sprint(r.HealthPort))+"/status", nil)
	if e != nil {
		return out, ErrOperation
	}
	client := &http.Client{Timeout: HealthRequestTimeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return out, ErrOperation
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, (1<<20)+1)).Decode(&out) != nil {
		return out, ErrOperation
	}
	return out, nil
}
func ready(role string, s lifecycle.Snapshot) bool {
	if !s.Live || s.Mode != "serving" {
		return false
	}
	caps := map[string][]string{"nginx": {lifecycle.Data}, "management": {lifecycle.Management}, "background-jobs": {lifecycle.GlobalJobs, lifecycle.LocalCleanup}, "log-query": {lifecycle.Query}}
	for _, cap := range caps[role] {
		if !s.Ready[cap] {
			return false
		}
	}
	return len(caps[role]) > 0
}
func (h LocalHost) Status(ctx context.Context) (upgrade.NodeState, error) {
	out := upgrade.NodeState{Ready: true, ControlReady: true, Images: map[string]string{}}
	if h.Configuration.Node.Validate() != nil {
		return out, ErrOperation
	}
	for _, role := range domain.NodeRoleNames() {
		s, e := h.snapshot(ctx, role)
		if e != nil || !ready(role, s) {
			out.Ready = false
			out.ControlReady = false
		}
		if role == "nginx" {
			out.ArtifactID = s.Details["artifact_id"]
			out.Generation = s.Details["generation"]
		}
		id, e := h.compose(ctx, "ps", "-a", "-q", role)
		if e != nil || strings.TrimSpace(string(id)) == "" {
			return out, ErrOperation
		}
		image, e := h.command(ctx, "inspect", "--format", "{{.Config.Image}}", strings.TrimSpace(string(id)))
		if e != nil {
			return out, e
		}
		out.Images[role] = strings.TrimSpace(string(image))
	}
	return out, nil
}
func (h LocalHost) control(ctx context.Context, role, path string, body any, out any) error {
	r, ok := h.Configuration.Node.Roles[role]
	if !ok {
		return ErrOperation
	}
	socket := filepath.Join(h.Configuration.StorageRoot, strings.TrimPrefix(r.ControlVolume, h.Configuration.Node.StoragePrefix+"-"), "control.sock")
	st, e := os.Lstat(socket)
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		return ErrOperation
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return e
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://owner"+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := client.Do(req)
	if e != nil {
		return ErrOperation
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrOperation
	}
	if out != nil && json.NewDecoder(io.LimitReader(response.Body, (1<<20)+1)).Decode(out) != nil {
		return ErrOperation
	}
	return nil
}
func (h LocalHost) config(role string) (bootstrap.Config, error) {
	var c bootstrap.Config
	path := h.Configuration.Node.Roles[role].ConfigFile
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 1<<20 || json.Unmarshal(b, &c) != nil {
		return c, ErrOperation
	}
	if c.NodeID != h.Configuration.Node.Node.ID || c.NodeEpoch != h.Configuration.Node.Node.Epoch || c.RuntimeProtocol != 1 {
		return c, ErrOperation
	}
	return c, nil
}
func (h LocalHost) management(ctx context.Context, s upgrade.Step) error {
	var target domain.NodeDeployment
	for _, n := range s.Targets {
		if n.Node == s.Node {
			target = n
		}
	}
	var desired struct {
		Digest string `json:"desired_digest"`
	}
	if h.control(ctx, "nginx", "/management-upstreams", map[string]any{"address": net.JoinHostPort(target.PrivateAddress, "9443"), "unavailable": s.Kind == "management-remove"}, &desired) != nil || len(desired.Digest) != 64 {
		return ErrOperation
	}
	for {
		actual, e := h.snapshot(ctx, "nginx")
		if e == nil && actual.Details["management_config_digest"] == desired.Digest {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrOperation
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// fileInRole resolves container secret references into that owning role's host
// secret directory. It never accepts arbitrary container/runtime paths.
func (h LocalHost) fileInRole(role, path string) ([]byte, error) {
	if filepath.Dir(path) != "/run/gatebeam" {
		return nil, ErrOperation
	}
	return os.ReadFile(filepath.Join(filepath.Dir(h.Configuration.Node.Roles[role].ConfigFile), filepath.Base(path)))
}
func (h LocalHost) verifyTLS(ctx context.Context, kind string) error {
	edge, e := h.config("nginx")
	if e != nil {
		return e
	}
	var host, port, trustFile string
	owner := "nginx"
	certificate, key := "", ""
	switch kind {
	case "verify-api":
		host, port, trustFile = edge.ManagementAPIName, "9443", edge.ManagementAPITrustFile
		certificate, key = edge.ManagementAPIClientCertificateFile, edge.ManagementAPIClientKeyFile
	case "verify-public":
		host, port, trustFile = edge.ManagementDomain, "443", edge.ManagementTrustFile
	case "verify-private":
		return h.externalCADirectory(ctx)
	default:
		return ErrOperation
	}
	roots, e := h.fileInRole(owner, trustFile)
	if e != nil {
		return ErrOperation
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		return ErrOperation
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host}
	if certificate != "" {
		cert, e := h.fileInRole("nginx", certificate)
		if e != nil {
			return ErrOperation
		}
		private, e := h.fileInRole("nginx", key)
		if e != nil {
			return ErrOperation
		}
		pair, e := tls.X509KeyPair(cert, private)
		clear(private)
		if e != nil {
			return ErrOperation
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	address := net.JoinHostPort(h.Configuration.Node.PrivateAddress, port)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	path := "/auth/session"
	expected := 401
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+path, nil)
	r, e := client.Do(req)
	if e != nil {
		return ErrOperation
	}
	defer r.Body.Close()
	if r.StatusCode != expected {
		return ErrOperation
	}
	return nil
}
func (h LocalHost) verify(ctx context.Context, kind string, images map[string]string, id string) error {
	ctx, cancel := context.WithTimeout(ctx, VerificationTimeout)
	defer cancel()
	for {
		good := true
		for _, role := range domain.NodeRoleNames() {
			s, e := h.snapshot(ctx, role)
			if e != nil || !ready(role, s) {
				good = false
			}
		}
		if good && h.verifyTLS(ctx, kind) == nil {
			for role, want := range images {
				id, e := h.compose(ctx, "ps", "-q", role)
				if e != nil {
					return e
				}
				actual, e := h.command(ctx, "inspect", "--format", "{{.Config.Image}}", strings.TrimSpace(string(id)))
				if e != nil || strings.TrimSpace(string(actual)) != want {
					return ErrOperation
				}
			}
			return h.functionalCanary(ctx, kind, id)
		}
		select {
		case <-ctx.Done():
			return ErrOperation
		case <-time.After(time.Second):
		}
	}
}
func (h LocalHost) checkCapacityLimits(ctx context.Context, evidence *domain.CapacityEvidence) error {
	if evidence == nil {
		return upgrade.ErrCapacity
	}
	matched := false
	for _, trial := range evidence.Trials {
		if trial.Node != h.Configuration.Node.Node {
			continue
		}
		matched = true
		for _, role := range domain.NodeRoleNames() {
			id, e := h.compose(ctx, "ps", "-a", "-q", role)
			if e != nil {
				return upgrade.ErrCapacity
			}
			raw, e := h.command(ctx, "inspect", "--format", "{{json .HostConfig}}", strings.TrimSpace(string(id)))
			var actual struct{ Memory, NanoCpus, PidsLimit int64 }
			if e != nil || json.Unmarshal(raw, &actual) != nil {
				return upgrade.ErrCapacity
			}
			want := trial.Limits[role]
			if actual.Memory != want.MemoryBytes || actual.NanoCpus != want.NanoCPUs || actual.PidsLimit != want.PIDs {
				return upgrade.ErrCapacity
			}
		}
	}
	if !matched {
		return upgrade.ErrCapacity
	}
	return nil
}

func (h LocalHost) verifyImageContract(ctx context.Context, image string) error {
	raw, e := h.command(ctx, "run", "--rm", "--network", "none", "--read-only", "--user", "101:101", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "64m", "--pids-limit", "32", "--entrypoint", "/usr/local/bin/gatebeam", image, "--runtime-contract")
	var v domain.RuntimeContract
	if e != nil || json.Unmarshal(raw, &v) != nil || v.ConfigurationFormat != 2 || v.RuntimeProtocol != 1 || v.BootFormat != domain.BootFormat || v.SchemaMin < 1 || v.SchemaMin > 27 || v.SchemaMax < 27 || v.RoleMin < 1 || v.RoleMin > 6 || v.RoleMax < 6 {
		return ErrOperation
	}
	return nil
}

func (h LocalHost) Execute(ctx context.Context, s upgrade.Step) error {
	if !stepID.MatchString(s.ID) || h.Configuration.Node.Validate() != nil {
		return ErrOperation
	}
	own := false
	for _, n := range s.Targets {
		if n.Node == h.Configuration.Node.Node && n.Instance == h.Configuration.Node.Instance && n.PrivateAddress == h.Configuration.Node.PrivateAddress {
			own = true
		}
	}
	if !own {
		return ErrOperation
	}
	if s.Kind != "management-remove" && s.Kind != "management-restore" && s.Kind != "precheck" && s.Kind != "recovery-check" && s.Node != h.Configuration.Node.Node {
		return ErrOperation
	}
	switch s.Kind {
	case "precheck", "recovery-check":
		if _, e := h.canarySpec(); e != nil {
			return e
		}
		if e := h.checkCapacityLimits(ctx, s.Capacity); e != nil {
			return e
		}
		plan, e := provisioning.BuildVolumes(h.Configuration.Node, h.Configuration.StorageRoot)
		if e != nil {
			return e
		}
		if e = provisioning.VerifyStorage(ctx, plan, storageinfra.DockerVolumes{}); e != nil {
			return e
		}
		status, e := h.Status(ctx)
		if e != nil || (s.Kind != "recovery-check" || s.Node != h.Configuration.Node.Node) && (!status.Ready || !status.ControlReady) {
			return ErrOperation
		}
		for _, n := range s.Targets {
			if n.Node == h.Configuration.Node.Node {
				for role, expected := range n.Roles {
					if status.Images[role] != expected.Image && !(s.Kind == "recovery-check" && s.Node == h.Configuration.Node.Node && status.Images[role] == s.Images[role]) {
						return ErrOperation
					}
				}
			}
		}
		for _, image := range s.Images {
			if _, e = h.command(ctx, "pull", image); e != nil {
				return e
			}
			if e = h.verifyImageContract(ctx, image); e != nil {
				return e
			}
		}
		for _, r := range h.Configuration.Node.Roles {
			if e = h.verifyImageContract(ctx, r.Image); e != nil {
				return e
			}
		}
		if s.Kind == "precheck" {
			if e = h.functionalCanary(ctx, "verify-public", s.ID); e != nil {
				return e
			}
			if e = h.statusCanary(ctx); e != nil {
				return e
			}
			return h.control(ctx, "background-jobs", "/capabilities/verify", struct{}{}, nil)
		}
		return nil
	case "management-remove", "management-restore":
		return h.management(ctx, s)
	case "drain":
		deadline := time.Now().Add(time.Duration(s.Seconds) * time.Second).UTC()
		for _, role := range domain.NodeRoleNames() {
			if len(s.Images) == 0 || s.Images[role] != "" {
				if role == "background-jobs" {
					if e := h.control(ctx, role, "/maintenance", map[string]bool{"enabled": true}, nil); e != nil {
						return e
					}
					continue
				}
				var ack lifecycle.Snapshot
				if e := h.control(ctx, role, "/drain", map[string]any{"deadline": deadline}, &ack); e != nil {
					return e
				}
				if ack.Mode != "draining" || ack.Deadline.After(deadline) || ack.Deadline.IsZero() {
					return ErrOperation
				}
			}
		}
		select {
		case <-ctx.Done():
			return ErrOperation
		case <-time.After(time.Until(deadline)):
			return nil
		}
	case "log-flush":
		entries, e := os.ReadDir(filepath.Join(h.Configuration.StorageRoot, "edge-logs"))
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".log") {
				continue
			}
			path := filepath.Join(h.Configuration.StorageRoot, "edge-logs", entry.Name())
			st, e := os.Lstat(path)
			if e != nil || !st.Mode().IsRegular() {
				return ErrOperation
			}
			f, e := os.Open(path)
			if e != nil {
				return e
			}
			e = errors.Join(f.Sync(), f.Close())
			if e != nil {
				return e
			}
		}
		if e = syncHostDir(filepath.Join(h.Configuration.StorageRoot, "edge-logs")); e != nil {
			return e
		}
		var cutoff []struct {
			NodeID, ID, Path, Fingerprint string
			Offset, Size                  int64
			Closed                        bool
		}
		if e = h.control(ctx, "background-jobs", "/logs/cutoff", struct{}{}, &cutoff); e != nil {
			return e
		}
		end := time.Now().Add(60 * time.Second)
		for {
			var receipt struct {
				Ready           bool `json:"ready"`
				ArchiveRequired bool `json:"archive_required"`
			}
			if e = h.control(ctx, "background-jobs", "/logs/cutoff/verify", cutoff, &receipt); e != nil {
				return e
			}
			if receipt.Ready {
				break
			}
			if time.Now().After(end) {
				return ErrOperation
			}
			select {
			case <-ctx.Done():
				return ErrOperation
			case <-time.After(200 * time.Millisecond):
			}
		}
		if len(s.Images) == 0 || s.Images["background-jobs"] != "" {
			deadline := time.Now().Add(time.Second).UTC()
			var ack lifecycle.Snapshot
			if e = h.control(ctx, "background-jobs", "/drain", map[string]any{"deadline": deadline}, &ack); e != nil || ack.Mode != "draining" || !ack.Deadline.Equal(deadline) {
				return ErrOperation
			}
			select {
			case <-ctx.Done():
				return ErrOperation
			case <-time.After(time.Until(deadline)):
			}
		}
		return nil
	case "update":
		return h.update(ctx, s)
	case "verify-api", "verify-private", "verify-public":
		return h.verify(ctx, s.Kind, s.Images, s.ID)
	case "observe":
		end := time.Now().Add(time.Duration(s.Seconds) * time.Second)
		for time.Now().Before(end) {
			if e := h.verify(ctx, "verify-public", s.Images, s.ID); e != nil {
				return e
			}
			select {
			case <-ctx.Done():
				return ErrOperation
			case <-time.After(time.Second):
			}
		}
		return nil
	default:
		return ErrOperation
	}
}

var imageEnv = map[string]string{"nginx": "GATEBEAM_NGINX_IMAGE", "management": "GATEBEAM_MANAGEMENT_IMAGE", "background-jobs": "GATEBEAM_JOBS_IMAGE", "log-query": "GATEBEAM_LOG_QUERY_IMAGE"}

func (h LocalHost) update(ctx context.Context, s upgrade.Step) error {
	if len(s.Images) == 0 {
		return ErrOperation
	}
	n := h.Configuration.Node
	for role, image := range s.Images {
		r, ok := n.Roles[role]
		if !ok {
			return ErrOperation
		}
		r.Image = image
		n.Roles[role] = r
	}
	if n.Validate() != nil {
		return ErrOperation
	}
	env, e := os.ReadFile(n.EnvironmentFile)
	if e != nil || len(env) > 1<<20 {
		return ErrOperation
	}
	lines := strings.Split(string(env), "\n")
	roles := []string{}
	for _, role := range domain.NodeRoleNames() {
		image, changed := s.Images[role]
		if !changed {
			continue
		}
		roles = append(roles, role)
		matches := 0
		for j, line := range lines {
			if strings.HasPrefix(line, imageEnv[role]+"=") {
				lines[j] = imageEnv[role] + "=" + image
				matches++
			}
		}
		if matches != 1 {
			return ErrOperation
		}
	}
	// Validate every selected config before the first replacement.
	configs := map[string][]byte{}
	for _, role := range roles {
		c, e := h.config(role)
		if e != nil {
			return e
		}
		c.ImageDigest = strings.Split(s.Images[role], "@")[1]
		raw, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		configs[n.Roles[role].ConfigFile] = append(raw, '\n')
	}
	configs[n.EnvironmentFile] = []byte(strings.Join(lines, "\n"))
	config := h.Configuration
	config.Node = n
	raw, e := json.MarshalIndent(config, "", "  ")
	if e != nil {
		return e
	}
	configs[h.ConfigurationFile] = append(raw, '\n')
	paths := make([]string, 0, len(configs))
	for path := range configs {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for index, path := range paths {
		old, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		backup := filepath.Join(h.Journal, fmt.Sprintf("%s-%02d.before", s.ID, index))
		if e = writeHostFile(backup, old, true); e != nil {
			return e
		}
	}
	for _, path := range paths {
		if e = replaceHostFile(path, configs[path]); e != nil {
			return e
		}
	}
	_, e = h.compose(ctx, append([]string{"up", "-d", "--no-build", "--no-deps", "--pull", "never", "--force-recreate"}, roles...)...)
	return e
}
