// Package smtp provides TLS-only mail submission, with no AUTH before verified TLS.
package smtp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"gatebeam/internal/modules/notification/domain"
	"net"
	"net/mail"
	mailsmtp "net/smtp"
	"strconv"
	"strings"
	"time"
)

type Sender struct{ Roots *x509.CertPool }

func (s Sender) Send(ctx context.Context, c domain.Channel, secret []byte, message string) (err error) {
	// Every protocol/peer error is collapsed before returning to application code.
	defer func() {
		if err != nil {
			err = domain.ErrDelivery
		}
	}()
	if strings.ContainsAny(c.From+c.Recipient+c.Username, "\r\n\x00") || strings.ContainsAny(c.Host, " /:@\r\n") || c.Port < 1 || c.Port > 65535 || len(secret) > 4096 || len(message) > 4096 {
		return domain.ErrDelivery
	}
	from, e := mail.ParseAddress(c.From)
	if e != nil || from.Address != c.From {
		return domain.ErrDelivery
	}
	to, e := mail.ParseAddress(c.Recipient)
	if e != nil || to.Address != c.Recipient {
		return domain.ErrDelivery
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if e != nil {
		return e
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	rawConnection := conn
	stop := context.AfterFunc(ctx, func() { rawConnection.Close() })
	defer stop()
	policy := &tls.Config{ServerName: c.Host, RootCAs: s.Roots, MinVersion: tls.VersionTLS12}
	if c.TLSMode == "implicit" {
		secured := tls.Client(conn, policy)
		if e = secured.HandshakeContext(ctx); e != nil {
			return e
		}
		conn = secured
	} else if c.TLSMode != "starttls" {
		return domain.ErrDelivery
	}
	client, e := mailsmtp.NewClient(conn, c.Host)
	if e != nil {
		return e
	}
	defer client.Close()
	if c.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return domain.ErrDelivery
		}
		if e = client.StartTLS(policy); e != nil {
			return e
		}
	}
	state, ok := client.TLSConnectionState()
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return domain.ErrDelivery
	}
	if c.Username != "" {
		if e = client.Auth(mailsmtp.PlainAuth("", c.Username, string(secret), c.Host)); e != nil {
			return e
		}
	}
	if e = client.Mail(from.Address); e != nil {
		return e
	}
	if e = client.Rcpt(to.Address); e != nil {
		return e
	}
	writer, e := client.Data()
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(writer, "From: %s\r\nTo: %s\r\nSubject: Gatebeam notification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", from.Address, to.Address, message)
	if e != nil {
		writer.Close()
		return e
	}
	if e = writer.Close(); e != nil {
		return e
	}
	// DATA acceptance is success even if the optional QUIT exchange fails.
	_ = client.Quit()
	return nil
}
