//go:build integration

package pki_test

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/pki"
	acmeapp "gatebeam/internal/modules/pki/application/acme"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Test-only subprocess configuration. Public responses remain standard OCSP/CRL;
// no fixture endpoint or process option is added to the product.
type statusProcessConfig struct {
	DatabaseURL, Schema, Online, Address string
	Config                               pki.Config
}

func serveStatusProcess(path string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var cfg statusProcessConfig
	if e = json.Unmarshal(b, &cfg); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dbCfg, e := pgxpool.ParseConfig(cfg.DatabaseURL)
	if e != nil {
		return e
	}
	dbCfg.ConnConfig.RuntimeParams["search_path"] = cfg.Schema
	dbCfg.MaxConns = 2
	db, e := pgxpool.NewWithConfig(ctx, dbCfg)
	if e != nil {
		return e
	}
	defer db.Close()
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: filepath.Join(cfg.Online, "issuer.pem"), RootFile: filepath.Join(cfg.Online, "root.pem"), SignerFile: filepath.Join(cfg.Online, "issuer.age"), IdentityFile: filepath.Join(cfg.Online, "identity.agekey")})
	if e != nil {
		return e
	}
	server, e := pki.NewServer(cfg.Config, db, issuer)
	if e != nil {
		return e
	}
	if e = server.RegisterStatus(ctx, db); e != nil {
		return e
	}
	// The same current-principal check used by production issuance must still
	// reject a disabled principal after this entirely new OS process starts.
	orders := acmeapp.NewOrders(postgres.NewRunner(db), repo.New(), pkicrypto.Random{}, nil, nil, nil)
	if _, e = orders.NewOrder(ctx, acmeapp.AccountRef{Directory: "client", ID: "client", Thumbprint: "client"}, []string{"native.internal.test"}); !errors.Is(e, acmeapp.ErrDenied) {
		return errors.New("disabled principal survived incorrectly")
	}
	listener, e := net.Listen("tcp", cfg.Address)
	if e != nil {
		return e
	}
	defer listener.Close()
	httpServer := &http.Server{Handler: server.StatusHandler(), ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	go func() { <-ctx.Done(); httpServer.Close() }()
	e = httpServer.Serve(listener)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func startStatusProcess(t *testing.T, cfg statusProcessConfig) (string, func()) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	cfg.Address = listener.Addr().String()
	listener.Close()
	path := filepath.Join(t.TempDir(), "status-process.json")
	b, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	write(t, path, b)
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, executable)
	cmd.Env = append(os.Environ(), "GATEBEAM_P4_STATUS_FIXTURE="+path)
	if e = cmd.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("status subprocess did not exit")
		}
	}
	t.Cleanup(stop)
	client := &http.Client{Timeout: 300 * time.Millisecond}
	base := "http://" + cfg.Address
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, e := client.Get(base + "/crl/root.der")
		if e == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				return base, stop
			}
		}
		select {
		case <-done:
			stopped = true
			cancel()
			t.Fatal("status subprocess failed before readiness")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	t.Fatal("status subprocess readiness deadline")
	return "", nil
}
