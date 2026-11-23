//go:build integration

package multinode

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func RunBackend() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-r.Context().Done():
				return
			case <-time.After(90 * time.Second):
			}
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			ticker := time.NewTicker(30 * time.Millisecond)
			defer ticker.Stop()
			for {
				w.Write([]byte("data: owned\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
				}
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("owned-business"))
	})
	server := &http.Server{Addr: ":8080", Handler: h, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case e := <-done:
		return e
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return server.Shutdown(c)
	}
}
