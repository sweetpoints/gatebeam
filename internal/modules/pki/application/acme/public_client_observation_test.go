//go:build integration

package acme_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The child is the test executable behind an owned fake Docker CLI. It serves
// only a localhost HTTP observation after controlled CLI startup overhead.
// Ordinary test invocation cannot enter this path through environment alone.
func init() {
	if filepath.Base(os.Args[0]) != "docker" || len(os.Args) < 2 || os.Args[1] != "exec" || os.Getenv("GATEBEAM_OWNER_OBSERVATION_CHILD") != "1" {
		return
	}
	address := os.Getenv("GATEBEAM_OWNER_OBSERVATION_URL")
	delay, err := strconv.Atoi(os.Getenv("GATEBEAM_OWNER_OBSERVATION_DELAY_MS"))
	endpoint, parseErr := url.Parse(address)
	if err != nil || delay < 0 || delay > 3000 || parseErr != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.User != nil {
		os.Exit(2)
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
	response, err := (&http.Client{Timeout: time.Second}).Get(address)
	if err != nil || response.StatusCode != http.StatusOK {
		os.Exit(2)
	}
	_, err = io.Copy(os.Stdout, response.Body)
	response.Body.Close()
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestNativeVersionObservationUsesFunctionalDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "owned/generation")
	}))
	t.Cleanup(server.Close)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(directory, "docker")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GATEBEAM_OWNER_OBSERVATION_CHILD", "1")
	t.Setenv("GATEBEAM_OWNER_OBSERVATION_URL", server.URL)
	t.Setenv("GATEBEAM_OWNER_OBSERVATION_DELAY_MS", "3000")
	edge := &publicEdge{name: "owned"}
	t.Run("healthy observation after CLI overhead remains inside ten seconds", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		if !edge.nativeVersionMatches(ctx, "owned/generation") {
			t.Fatal("healthy actual HTTP version rejected before the functional deadline")
		}
	})
	t.Run("expiry still rejects the observation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if edge.nativeVersionMatches(ctx, "owned/generation") {
			t.Fatal("expired observation accepted")
		}
		if ctx.Err() == nil {
			t.Fatal("observation did not exercise deadline expiry")
		}
	})
	t.Setenv("GATEBEAM_OWNER_OBSERVATION_DELAY_MS", "0")
	t.Run("different version remains rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		if edge.nativeVersionMatches(ctx, "different/generation") {
			t.Fatal("different native version accepted")
		}
		if ctx.Err() != nil {
			t.Fatal("different-version check ended through deadline instead of version comparison")
		}
	})
}
