//go:build integration

package delivery_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/domain"
	smtpAdapter "gatebeam/internal/modules/notification/infrastructure/smtp"
	telegramAdapter "gatebeam/internal/modules/notification/infrastructure/telegram"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual provider adapters communicate only with these owned loopback servers.
func localProviders(t *testing.T) (app.Sender, app.Sender, domain.Channel, *atomic.Bool, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var tgCalls, smtpCalls atomic.Int32
	fail := &atomic.Bool{}
	fail.Store(true)
	telegram := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tgCalls.Add(1)
		if r.URL.Path != "/bot123:SECRET/sendMessage" {
			t.Error("wrong fixed provider path")
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(telegram.Close)
	transport := telegram.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "api.telegram.org:443" {
			return nil, fmt.Errorf("unexpected provider")
		}
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(telegram.URL, "https://"))
	}
	listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: telegram.TLS.Certificates, MinVersion: tls.VersionTLS12})
	if e != nil {
		t.Fatal(e)
	}
	stopped := make(chan struct{})
	t.Cleanup(func() { listener.Close(); <-stopped })
	go func() {
		defer close(stopped)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprint(conn, "220 owned SMTP\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						fmt.Fprint(conn, "250-owned\r\n250 AUTH PLAIN\r\n")
					case strings.HasPrefix(line, "AUTH"):
						fmt.Fprint(conn, "235 okay\r\n")
					case strings.HasPrefix(line, "DATA"):
						fmt.Fprint(conn, "354 data\r\n")
						for {
							line, e = reader.ReadString('\n')
							if e != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							if strings.Contains(line, "RAW_SOURCE") {
								t.Error("raw source sent")
							}
						}
						smtpCalls.Add(1)
						if fail.Load() {
							fmt.Fprint(conn, "451 SECRET provider failure\r\n")
						} else {
							fmt.Fprint(conn, "250 accepted\r\n")
						}
					case strings.HasPrefix(line, "QUIT"):
						fmt.Fprint(conn, "221 bye\r\n")
						return
					default:
						fmt.Fprint(conn, "250 okay\r\n")
					}
				}
			}()
		}
	}()
	smtpChannel := domain.Channel{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, TLSMode: "implicit", From: "sender@example.test", Recipient: "receiver@example.test", Username: "test"}
	return telegramAdapter.Sender{Client: &http.Client{Transport: transport}}, smtpAdapter.Sender{Roots: telegram.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}, smtpChannel, fail, &tgCalls, &smtpCalls
}
