//go:build integration

package multinode

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestRouterConnectionUsesFixtureLifetimeAndCancelsIdleCopies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		client, clientProxy := net.Pipe()
		upstreamProxy, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		forwarded := make(chan struct{})
		go func() {
			forwardRouterConnection(ctx, clientProxy, upstreamProxy)
			close(forwarded)
		}()
		serverResult := make(chan error, 1)
		go func() {
			request := make([]byte, len("owned-request"))
			if _, err := io.ReadFull(server, request); err != nil {
				serverResult <- err
				return
			}
			if string(request) != "owned-request" {
				serverResult <- errors.New("port mapping altered the request")
				return
			}
			time.Sleep(6 * time.Minute)
			_, err := server.Write([]byte("owned-response"))
			serverResult <- err
		}()
		if _, err := client.Write([]byte("owned-request")); err != nil {
			t.Fatal("port mapping did not forward the request", err)
		}
		time.Sleep(6 * time.Minute)
		response := make([]byte, len("owned-response"))
		if _, err := io.ReadFull(client, response); err != nil || string(response) != "owned-response" {
			t.Fatal("port mapping injected a connection-age failure", err)
		}
		if err := <-serverResult; err != nil {
			t.Fatal("port mapping lost the delayed response", err)
		}
		cancel()
		select {
		case <-forwarded:
		case <-time.After(time.Second):
			t.Fatal("fixture cancellation left idle forwarding copies alive")
		}
	})
}
