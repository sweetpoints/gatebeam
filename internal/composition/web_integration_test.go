//go:build integration

package composition

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	deployapp "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	deploypg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/identity"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestWebBrowser(t *testing.T) {
	if os.Getenv("GATEBEAM_WEB_ACCEPTANCE") != "1" {
		t.Skip("explicit browser acceptance runs via scripts/check-web.sh auth")
	}
	p := testkit.Postgres(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "identity")
	if e := secrets.EnsureIdentity(key); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	service := identity.New(p, se)
	challenge, e := service.Bootstrap(context.Background(), "browser-admin")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	origin := "http://" + listener.Addr().String()
	pkiConfig := bootstrap.Config{}
	pkiFixture := map[string]any{}
	if os.Getenv("GATEBEAM_WEB_SUITE") == "pki" {
		pkiConfig, pkiFixture = webPKI(t, p)
	}
	if os.Getenv("GATEBEAM_WEB_SUITE") == "operations" {
		pkiConfig, pkiFixture = webOperations(t, p)
	}
	handler, e := newAPIHandlerWithPKI(p, se, nil, pkiConfig, authHTTP.Config{Origin: origin})
	if e != nil {
		t.Fatal(e)
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(withWeb(handler, os.DirFS(filepath.Join(root, "web/dist"))))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	var entropy [24]byte
	if _, e = rand.Read(entropy[:]); e != nil {
		t.Fatal(e)
	}
	signalFile := filepath.Join(dir, "disable")
	scopeSignal := filepath.Join(dir, "scope")
	fixture := map[string]any{"name": "browser-admin", "password": hex.EncodeToString(entropy[:]), "enrollment": challenge, "origin": origin, "disableSignal": signalFile}
	for k, v := range pkiFixture {
		fixture[k] = v
	}
	if os.Getenv("GATEBEAM_WEB_SUITE") == "ingress" || os.Getenv("GATEBEAM_WEB_SUITE") == "pki" || os.Getenv("GATEBEAM_WEB_SUITE") == "operations" {
		fixture["scopeSignal"] = scopeSignal
		webEdge(t, p, fixture)
	}
	data, e := json.Marshal(fixture)
	if e != nil {
		t.Fatal("fixture encoding failed")
	}
	fixturePath := filepath.Join(dir, "fixture.json")
	if e = os.WriteFile(fixturePath, data, 0600); e != nil {
		t.Fatal(e)
	}
	browserRunBudget := 75 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		browserRunBudget *= 12
	}
	ctx, cancel := context.WithTimeout(context.Background(), browserRunBudget)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if data, err := os.ReadFile(scopeSignal); err == nil {
					var scope struct {
						SiteID              string `json:"site_id"`
						HistorySiteID       string `json:"history_site_id"`
						HistoryHiddenSiteID string `json:"history_hidden_site_id"`
					}
					if json.Unmarshal(data, &scope) == nil {
						// Populate the bounded raw ACL gap through the release owner
						// in one real transaction, avoiding 105 HTTP setup round trips.
						if scope.HistoryHiddenSiteID != "" {
							owner := release.New(deploypg.New(), identifiers.Generator{})
							if err := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
								for range 105 {
									if _, err := owner.PrepareWithin(sc, release.PrepareInput{Snapshot: deployapp.Snapshot{Version: "deployment/v1"}, SelectedSiteIDs: []string{scope.HistoryHiddenSiteID}, AffectedSiteIDs: []string{scope.HistoryHiddenSiteID}, Expected: map[string]int64{"site:" + scope.HistoryHiddenSiteID: 1}}); err != nil {
										return err
									}
								}
								return nil
							}); err != nil {
								t.Error("fixture release pagination setup failed", err)
								return
							}
						}
						c, stop := context.WithTimeout(ctx, 3*time.Second)
						tx, err := p.Begin(c)
						if err == nil {
							role := "editor"
							if scope.HistorySiteID != "" {
								role = "publisher"
							}
							_, err = tx.Exec(c, "UPDATE identity_accounts SET role=$1 WHERE name='browser-admin'", role)
							if err == nil {
								_, err = tx.Exec(c, "INSERT INTO identity_grants(account_id,kind,resource_id) SELECT id,'site',$1 FROM identity_accounts WHERE name='browser-admin'", scope.SiteID)
							}
							if err == nil && scope.HistorySiteID != "" {
								_, err = tx.Exec(c, "INSERT INTO identity_grants(account_id,kind,resource_id) SELECT id,'site',$1 FROM identity_accounts WHERE name='browser-admin'", scope.HistorySiteID)
							}
							if err == nil {
								err = tx.Commit(c)
							} else {
								_ = tx.Rollback(c)
							}
						}
						stop()
						if err != nil {
							t.Error("fixture scope update failed")
						}
					}
					return
				}
				if _, e := os.Stat(signalFile); e == nil {
					c, stop := context.WithTimeout(ctx, 3*time.Second)
					_, err := p.Exec(c, "UPDATE identity_accounts SET state='disabled',auth_version=auth_version+1 WHERE name=$1", "browser-admin")
					stop()
					if err != nil {
						t.Error("fixture disable failed")
					}
					return
				}
			}
		}
	}()
	suite := os.Getenv("GATEBEAM_WEB_SUITE")
	if suite != "ingress" && suite != "pki" && suite != "operations" {
		suite = "auth"
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "web/node_modules/.bin/playwright"), "test", "tests/"+suite+".spec.ts")
	cmd.Dir = filepath.Join(root, "web")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "FORCE_COLOR=") && !strings.HasPrefix(value, "NO_COLOR=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GATEBEAM_WEB_URL="+origin, "GATEBEAM_WEB_FIXTURE="+fixturePath, "GATEBEAM_WEB_RESULTS="+filepath.Join(dir, "results"), "PLAYWRIGHT_NO_COPY_PROMPT=1")
	// Assertions deliberately never print credentials; browser tracing is disabled.
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	runError := cmd.Run()
	safe := strings.ReplaceAll(output.String(), fixture["password"].(string), "[redacted password]")
	safe = strings.ReplaceAll(safe, challenge.ProvisioningURI, "[redacted provisioning URI]")
	safe = regexp.MustCompile(`[A-Za-z0-9_-]{43}`).ReplaceAllString(safe, "[redacted credential]")
	safe = regexp.MustCompile(`[A-Z2-7]{32,}`).ReplaceAllString(safe, "[redacted TOTP seed]")
	safe = regexp.MustCompile(`\b[0-9]{6}\b`).ReplaceAllString(safe, "[redacted OTP]")
	t.Log(safe)
	if runError != nil {
		exitCode := -1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		t.Fatalf("real browser acceptance failed: exit=%d aggregate_deadline_expired=%t", exitCode, ctx.Err() != nil)
	}
}
