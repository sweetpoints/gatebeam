//go:build integration

package multinode

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/infrastructure/operations"
	"gatebeam/internal/platform/lifecycle"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestFixtureHealthObserversUseProductionRequestWindow(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	synctest.Test(t, func(t *testing.T) {
		http.DefaultTransport = preparationTransport(func(r *http.Request) (*http.Response, error) {
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-time.After(1500 * time.Millisecond):
			}
			raw, _ := json.Marshal(lifecycle.Snapshot{Live: true, Mode: "serving"})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header), Request: r}, nil
		})
		node := &Node{ports: map[string]string{"/" + strconv.Itoa(HealthPorts["nginx"]): "127.0.0.1:19091"}}
		if state, err := node.ProbeHealth(t, "nginx"); err != nil || !state.Live {
			t.Fatal("fixture status rejected a response inside the production request window", err)
		}
		observer := &UpgradeOperations{T: t}
		if state, err := observer.snapshot(t.Context(), node, "nginx"); err != nil || !state.Live {
			t.Fatal("upgrade status rejected a response inside the production request window", err)
		}
		node.Wait(t, "nginx", lifecycle.Data)
	})
}

func TestManagementConfirmationRequiresLoadedDigestWithinProductionObservationWindow(t *testing.T) {
	for _, scenario := range []string{"delayed-target", "wrong-target", "parent-cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			original := http.DefaultTransport
			defer func() { http.DefaultTransport = original }()
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				target := strings.Repeat("a", 64)
				http.DefaultTransport = preparationTransport(func(r *http.Request) (*http.Response, error) {
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-time.After(1500 * time.Millisecond):
					}
					digest := strings.Repeat("b", 64)
					if scenario == "delayed-target" && time.Since(started) >= 10*time.Second {
						digest = target
					}
					raw, _ := json.Marshal(lifecycle.Snapshot{Details: map[string]string{"management_config_digest": digest}})
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header), Request: r}, nil
				})
				parentBudget := 10 * time.Minute
				if scenario == "parent-cancelled" {
					parentBudget = 15 * time.Second
				}
				ctx, cancel := context.WithTimeout(t.Context(), parentBudget)
				defer cancel()
				node := &Node{ports: map[string]string{"/" + strconv.Itoa(HealthPorts["nginx"]): "127.0.0.1:19091"}}
				observer := &UpgradeOperations{T: t}
				state, observations, err := observer.waitManagementDigest(ctx, node, target)
				elapsed := time.Since(started)
				if observations < 2 {
					t.Fatal("a desired-state acknowledgement skipped actual loaded-digest observation")
				}
				if scenario == "delayed-target" {
					if err != nil || state.Details["management_config_digest"] != target || elapsed < 10*time.Second || elapsed >= operations.OperationObservationTimeout {
						t.Fatal("a target loaded after the old eight-second guard was not confirmed", err)
					}
					return
				}
				limit := operations.OperationObservationTimeout
				if scenario == "parent-cancelled" {
					limit = parentBudget
				}
				if !errors.Is(err, context.DeadlineExceeded) || elapsed != limit {
					t.Fatal("wrong target was accepted or observation ignored its finite/parent deadline", err, elapsed)
				}
			})
		})
	}
}
