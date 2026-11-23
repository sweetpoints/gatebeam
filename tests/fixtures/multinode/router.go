//go:build integration

package multinode

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RouterMain is test-only raw TCP forwarding that models per-VM port mappings.
// It owns no TLS material and never terminates/replays a protocol request.
func RouterMain(path string) error {
	raw, e := os.ReadFile(path)
	if path == "env" {
		raw = []byte(os.Getenv("GATEBEAM_TEST_TCP_ROUTES_JSON"))
		e = nil
	}
	if e != nil || len(raw) > 16384 {
		return errors.New("invalid owned router input")
	}
	routes := map[string]string{}
	if json.Unmarshal(raw, &routes) != nil || len(routes) == 0 || len(routes) > 16 {
		return errors.New("invalid owned router routes")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listeners := []net.Listener{}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	for address, target := range routes {
		listener, e := net.Listen("tcp", address)
		if e != nil {
			return e
		}
		listeners = append(listeners, listener)
		go func(l net.Listener, destination string) {
			for {
				client, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					upstream, e := net.DialTimeout("tcp", destination, time.Second)
					if e != nil {
						client.Close()
						return
					}
					forwardRouterConnection(ctx, client, upstream)
				}()
			}
		}(listener, target)
	}
	<-ctx.Done()
	return nil
}

// A port mapping must not inject a five-minute connection fault into unrelated
// upgrade scenarios. Application deadlines and explicit fault injection remain
// authoritative. Fixture cancellation still closes both directions immediately.
func forwardRouterConnection(ctx context.Context, client, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		upstream.Close()
	})
	defer stop()
	done := make(chan struct{})
	go func() {
		io.Copy(upstream, client)
		if c, ok := upstream.(*net.TCPConn); ok {
			c.CloseWrite()
		}
		close(done)
	}()
	io.Copy(client, upstream)
	if c, ok := client.(*net.TCPConn); ok {
		c.CloseWrite()
	}
	<-done
}
