package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	runtimebootstrap "gatebeam/internal/modules/deployment/infrastructure/bootstrap"
	"gatebeam/internal/modules/observability"
	logdomain "gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/queryipc"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/objectstore"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type roleHealth struct {
	Address    string
	servers    []*http.Server
	socket     string
	socketInfo os.FileInfo
}

func (h *roleHealth) Close() {
	for _, server := range h.servers {
		_ = server.Close()
	}
	if h.socketInfo != nil {
		if info, e := os.Lstat(h.socket); e == nil && os.SameFile(info, h.socketInfo) {
			_ = os.Remove(h.socket)
		}
	}
}
func healthHandler(state *lifecycle.State) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		if !state.Live() {
			w.WriteHeader(503)
		}
		_, _ = io.WriteString(w, "live")
	})
	mux.HandleFunc("GET /readyz/{capability}", func(w http.ResponseWriter, r *http.Request) {
		capability := r.PathValue("capability")
		ready := state.Ready(capability)
		if capability == "ca" {
			ready = state.Ready(lifecycle.ACME) && state.Ready(lifecycle.Status)
		}
		if !ready {
			w.WriteHeader(503)
		}
		_, _ = io.WriteString(w, "ready")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.Snapshot())
	})
	return mux
}
func decodeControl(w http.ResponseWriter, r *http.Request, value any) error {
	return decodeControlLimit(w, r, value, 4096)
}
func decodeControlLimit(w http.ResponseWriter, r *http.Request, value any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(value); e != nil {
		return e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid command")
	}
	return nil
}

// Capability errors can contain credentials or private query paths. Only
// fixed classes enter operational failure logs; the control response is unchanged.
func queryCapabilityFailureClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, logdomain.ErrQueryTimeout):
		return "timeout"
	case errors.Is(err, logdomain.ErrQueryBusy):
		return "busy"
	case errors.Is(err, pgx.ErrNoRows):
		return "missing-object"
	case errors.Is(err, logdomain.ErrIncomplete):
		return "incomplete"
	case errors.Is(err, logdomain.ErrInvalid):
		return "invalid"
	case errors.Is(err, logdomain.ErrCapacity):
		return "capacity"
	case errors.Is(err, queryipc.ErrUnavailable):
		return "unavailable"
	default:
		return "failed"
	}
}

func controlHandler(cfg bootstrap.Config, state *lifecycle.State) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /status", healthHandler(state))
	mux.HandleFunc("POST /maintenance", func(w http.ResponseWriter, r *http.Request) {
		var command struct {
			Enabled *bool `json:"enabled"`
		}
		if decodeControl(w, r, &command) != nil || command.Enabled == nil {
			http.Error(w, "invalid command", 400)
			return
		}
		state.SetMaintenance(*command.Enabled)
		w.WriteHeader(200)
	})
	mux.HandleFunc("POST /management-upstreams", func(w http.ResponseWriter, r *http.Request) {
		var command struct {
			Address     string `json:"address"`
			Unavailable *bool  `json:"unavailable"`
		}
		if cfg.Mode != "edge" || cfg.RuntimeProtocol != 1 || cfg.ManagementAPIStateFile == "" {
			http.NotFound(w, r)
			return
		}
		if decodeControl(w, r, &command) != nil || command.Unavailable == nil {
			http.Error(w, "invalid command", 400)
			return
		}
		primary, peer, additional, e := managementTargets(cfg)
		if e != nil {
			http.Error(w, "invalid target policy", 503)
			return
		}
		saved, e := runtimebootstrap.UpdateManagementState(cfg.ManagementAPIStateFile, primary, peer, command.Address, *command.Unavailable, additional...)
		if e != nil {
			http.Error(w, "maintenance state unavailable", 503)
			return
		}
		queueManagementConfiguration(w, r, cfg, saved)
	})
	mux.HandleFunc("POST /management-peers", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Mode != "edge" || cfg.RuntimeProtocol != 1 || cfg.ManagementAPIStateFile == "" || cfg.ManagementAPIName == "" {
			http.NotFound(w, r)
			return
		}
		var command struct {
			Address string `json:"address"`
		}
		if decodeControl(w, r, &command) != nil || command.Address == "" {
			http.Error(w, "invalid command", 400)
			return
		}
		primary, peer, additional, err := managementTargets(cfg)
		if err != nil {
			http.Error(w, "invalid target policy", 503)
			return
		}
		protected := make([]netip.Prefix, 0, len(cfg.ProtectedNetworks))
		for _, raw := range cfg.ProtectedNetworks {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				http.Error(w, "invalid protection policy", 503)
				return
			}
			protected = append(protected, prefix)
		}
		saved, err := runtimebootstrap.RegisterManagementPeer(cfg.ManagementAPIStateFile, primary, peer, command.Address, protected, additional...)
		if err != nil {
			http.Error(w, "management endpoint cannot be staged", 409)
			return
		}
		queueManagementConfiguration(w, r, cfg, saved)
	})
	mux.HandleFunc("POST /capabilities/verify", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Mode != "worker" || cfg.RuntimeProtocol != 1 || !state.Accepts(lifecycle.GlobalJobs) {
			http.Error(w, "capability unavailable", 503)
			return
		}
		var command struct{}
		if decodeControl(w, r, &command) != nil {
			http.Error(w, "invalid command", 400)
			return
		}
		started := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		p, e := postgres.Open(ctx, cfg)
		if e != nil {
			http.Error(w, "capability unavailable", 503)
			return
		}
		defer p.Close()
		databaseElapsed := time.Since(started)
		phase := time.Now()
		if e = verifyRoleHistory(ctx, cfg, p); e != nil {
			http.Error(w, "capability unavailable", 503)
			return
		}
		historyElapsed := time.Since(phase)
		phase = time.Now()
		if cfg.ArchiveCredentialsFile != "" {
			credentials, e := objectstore.LoadConfig(cfg.ArchiveCredentialsFile)
			if e != nil || objectstore.VerifyWriteRead(ctx, credentials, cfg.NodeID) != nil {
				http.Error(w, "archive capability unavailable", 503)
				return
			}
		}
		archiveElapsed := time.Since(phase)
		phase = time.Now()
		if e = observability.VerifyQueryCapability(ctx, p, cfg.NodeID, cfg.QuerySocket, cfg.ArchiveCredentialsFile != ""); e != nil {
			fmt.Fprintf(os.Stderr, "gatebeam query capability failure class=%s elapsed_ms=%d deadline_expired=%t database_ms=%d history_ms=%d archive_ms=%d query_ms=%d\n", queryCapabilityFailureClass(e), time.Since(started).Milliseconds(), errors.Is(ctx.Err(), context.DeadlineExceeded), databaseElapsed.Milliseconds(), historyElapsed.Milliseconds(), archiveElapsed.Milliseconds(), time.Since(phase).Milliseconds())
			http.Error(w, "query capability unavailable", 503)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /logs/cutoff", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Mode != "worker" || cfg.RuntimeProtocol != 1 || !state.Accepts(lifecycle.LocalCleanup) {
			http.Error(w, "cleanup unavailable", 503)
			return
		}
		var command struct{}
		if decodeControl(w, r, &command) != nil {
			http.Error(w, "invalid command", 400)
			return
		}
		segments, e := observability.CaptureLogCutoff(r.Context(), cfg.LogDirectory, cfg.NodeID)
		if e != nil {
			http.Error(w, "cutoff unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(segments)
	})
	mux.HandleFunc("POST /logs/cutoff/verify", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Mode != "worker" || cfg.RuntimeProtocol != 1 || !state.Accepts(lifecycle.LocalCleanup) {
			http.Error(w, "cleanup unavailable", 503)
			return
		}
		var segments []logdomain.Segment
		if decodeControlLimit(w, r, &segments, 1<<20) != nil {
			http.Error(w, "invalid cutoff", 400)
			return
		}
		pool, e := postgres.Open(r.Context(), cfg)
		if e != nil {
			http.Error(w, "cleanup unavailable", 503)
			return
		}
		defer pool.Close()
		ready, e := observability.VerifyLogCutoff(r.Context(), pool, cfg.NodeID, segments, cfg.ArchiveCredentialsFile != "")
		if e != nil {
			http.Error(w, "cleanup unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ready": ready, "archive_required": cfg.ArchiveCredentialsFile != ""})
	})
	mux.HandleFunc("POST /drain", func(w http.ResponseWriter, r *http.Request) {
		var command struct {
			Deadline time.Time `json:"deadline"`
		}
		if decodeControl(w, r, &command) != nil {
			http.Error(w, "invalid command", 400)
			return
		}
		deadline := command.Deadline
		now := time.Now()
		if deadline.IsZero() {
			deadline = now.Add(drainDuration(cfg))
		}
		if !deadline.After(now) || deadline.After(now.Add(300*time.Second)) {
			http.Error(w, "invalid deadline", 400)
			return
		}
		state.BeginDrain(deadline)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.Snapshot())
	})
	return mux
}
func queueManagementConfiguration(w http.ResponseWriter, r *http.Request, cfg bootstrap.Config, saved runtimebootstrap.ManagementState) {
	step, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pool, err := postgres.Open(step, cfg)
	if err != nil {
		http.Error(w, "control unavailable", 503)
		return
	}
	defer pool.Close()
	digest := saved.Digest()
	err = postgres.NewRunner(pool).Within(step, func(sc transaction.Scope) error {
		_, err := jobs.New(pool).EnqueueTargetWithin(sc, "deployment.node.generation.v1", "management/"+digest,
			json.RawMessage(`{"kind":"management"}`), jobs.ClaimTarget{NodeID: cfg.NodeID, Epoch: cfg.NodeEpoch})
		return err
	})
	if err != nil {
		http.Error(w, "control unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	_ = json.NewEncoder(w).Encode(map[string]string{"desired_digest": digest})
}

func drainDuration(cfg bootstrap.Config) time.Duration {
	seconds := cfg.DrainSeconds
	if seconds == 0 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

// roleHTTPServer keeps health and owner transport policy in one constructor.
func roleHTTPServer(handler http.Handler, ownerControl bool) *http.Server {
	writeTimeout := 3 * time.Second
	if ownerControl {
		// Owner operations retain their independent five-second work budget.
		// Give the response time to reach the existing eight-second client.
		writeTimeout = 8 * time.Second
	}
	return &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: writeTimeout, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
}

func startRoleHealth(ctx context.Context, cfg bootstrap.Config, state *lifecycle.State) (h *roleHealth, err error) {
	if cfg.DrainSeconds < 0 || cfg.DrainSeconds > 300 {
		return nil, errors.New("invalid drain deadline")
	}
	h = &roleHealth{}
	defer func(owned *roleHealth) {
		if err != nil {
			owned.Close()
		}
	}(h)
	serve := func(listener net.Listener, handler http.Handler, ownerControl bool) {
		server := roleHTTPServer(handler, ownerControl)
		h.servers = append(h.servers, server)
		go func() { _ = server.Serve(listener) }()
	}
	if cfg.HealthListen != "" {
		address, e := netip.ParseAddrPort(cfg.HealthListen)
		if e != nil || (!address.Addr().IsPrivate() && !address.Addr().IsLoopback()) {
			return nil, errors.New("health listener must be private")
		}
		listener, e := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.HealthListen)
		if e != nil {
			return nil, errors.New("private health listener unavailable")
		}
		h.Address = listener.Addr().String()
		serve(listener, healthHandler(state), false)
	}
	if cfg.ControlSocket != "" {
		path := filepath.Clean(cfg.ControlSocket)
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return nil, errors.New("invalid deployment control socket")
		}
		parent := filepath.Dir(path)
		resolved, e := filepath.EvalSymlinks(parent)
		if e != nil || resolved != parent {
			return nil, errors.New("control socket directory must be canonical")
		}
		info, e := os.Stat(parent)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("control socket directory must be private")
		}
		if old, e := os.Lstat(path); e == nil {
			stat, ok := old.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Geteuid()) || old.Mode()&os.ModeSocket == 0 {
				return nil, errors.New("unowned control socket path")
			}
			c, e := net.DialTimeout("unix", path, 200*time.Millisecond)
			if e == nil {
				c.Close()
				return nil, errors.New("control socket already active")
			}
			if e = os.Remove(path); e != nil {
				return nil, e
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		listener, e := net.Listen("unix", path)
		if e != nil {
			return nil, e
		}
		if e = os.Chmod(path, 0600); e != nil {
			listener.Close()
			return nil, e
		}
		h.socket = path
		h.socketInfo, e = os.Lstat(path)
		if e != nil {
			listener.Close()
			return nil, e
		}
		serve(listener, controlHandler(cfg, state), true)
	}
	return h, nil
}
