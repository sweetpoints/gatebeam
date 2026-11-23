package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"gatebeam/internal/modules/notification/domain"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestImplicitTLSAndNoPlaintextAUTH(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates
	roots := fixture.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	fixture.Close()
	for _, secure := range []bool{false, true} {
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var auth atomic.Bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if secure {
					conn = tls.Server(conn, &tls.Config{Certificates: cert, MinVersion: tls.VersionTLS12})
				}
				fmt.Fprint(conn, "220 local fake SMTP\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						fmt.Fprint(conn, "250-local\r\n250 AUTH PLAIN\r\n")
					case strings.HasPrefix(line, "AUTH"):
						auth.Store(true)
						fmt.Fprint(conn, "235 authenticated\r\n")
					case strings.HasPrefix(line, "DATA"):
						fmt.Fprint(conn, "354 data\r\n")
						for {
							v, e := reader.ReadString('\n')
							if e != nil {
								return
							}
							if v == ".\r\n" {
								break
							}
						}
						fmt.Fprint(conn, "250 accepted\r\n")
					case strings.HasPrefix(line, "QUIT"):
						fmt.Fprint(conn, "221 bye\r\n")
						return
					default:
						fmt.Fprint(conn, "250 okay\r\n")
					}
				}
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			mode := "starttls"
			if secure {
				mode = "implicit"
			}
			c := domain.Channel{Host: "127.0.0.1", Port: port, TLSMode: mode, From: "sender@example.test", Recipient: "receiver@example.test", Username: "test-user"}
			sender := Sender{Roots: roots}
			err = sender.Send(t.Context(), c, []byte("SECRET"), "fixed safe notification")
			if secure && err != nil {
				t.Fatal(err)
			}
			if !secure && (err != domain.ErrDelivery || auth.Load()) {
				t.Fatal("plaintext authentication allowed", err)
			}
			<-done
		})
	}
}

func TestUntrustedTLSNeverAuthenticates(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates
	fixture.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprint(c, "220 owned\r\n")
	}()
	c := domain.Channel{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, TLSMode: "implicit", From: "sender@example.test", Recipient: "receiver@example.test", Username: "test"}
	if err = (Sender{}).Send(t.Context(), c, []byte("SECRET"), "safe"); err != domain.ErrDelivery {
		t.Fatal("untrusted TLS accepted", err)
	}
	<-done
}

func TestSTARTTLSAuthenticatesOnlyAfterVerifiedUpgrade(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates
	roots := fixture.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	fixture.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan struct{})
	var secured atomic.Bool
	var authenticated atomic.Bool
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
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
				if secured.Load() {
					fmt.Fprint(conn, "250-owned\r\n250 AUTH PLAIN\r\n")
				} else {
					fmt.Fprint(conn, "250-owned\r\n250 STARTTLS\r\n")
				}
			case strings.HasPrefix(line, "STARTTLS"):
				fmt.Fprint(conn, "220 begin TLS\r\n")
				upgraded := tls.Server(conn, &tls.Config{Certificates: cert, MinVersion: tls.VersionTLS12})
				if e = upgraded.Handshake(); e != nil {
					return
				}
				conn = upgraded
				reader = bufio.NewReader(conn)
				secured.Store(true)
			case strings.HasPrefix(line, "AUTH"):
				if !secured.Load() {
					t.Error("AUTH before TLS")
				}
				authenticated.Store(true)
				fmt.Fprint(conn, "235 accepted\r\n")
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
				}
				fmt.Fprint(conn, "250 accepted\r\n")
			case strings.HasPrefix(line, "QUIT"):
				fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprint(conn, "250 okay\r\n")
			}
		}
	}()
	c := domain.Channel{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, TLSMode: "starttls", From: "sender@example.test", Recipient: "receiver@example.test", Username: "test"}
	if e = (Sender{Roots: roots}).Send(t.Context(), c, []byte("SECRET"), "safe"); e != nil {
		t.Fatal(e)
	}
	<-done
	if !secured.Load() || !authenticated.Load() {
		t.Fatal("TLS/auth exchange missing")
	}
}
