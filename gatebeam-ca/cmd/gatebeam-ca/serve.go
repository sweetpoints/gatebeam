package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"gatebeam-ca/internal/modules/pki"
	pkicrypto "gatebeam-ca/internal/modules/pki/infrastructure/crypto"
	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/tlsidentity"
)

func serve(ctx context.Context, c config) error {
	addr, err := privateListen(c.Listen)
	if err != nil {
		return fmt.Errorf("ACME: %w", err)
	}
	statusAddr, err := privateListen(c.StatusListen)
	if err != nil {
		return fmt.Errorf("certificate status: %w", err)
	}
	hostname, err := originHost(c.Origin, "https")
	if err != nil {
		return err
	}
	if _, err := originHost(c.StatusOrigin, "http"); err != nil {
		return err
	}
	if c.TLSTrustFile == "" {
		c.TLSTrustFile = c.RootFile
	}
	loader, err := tlsidentity.New(tlsidentity.Config{
		CertificateFile: c.TLSCertificateFile, KeyFile: c.TLSKeyFile,
		TrustFile: c.TLSTrustFile, ServerName: hostname,
	})
	if err != nil {
		return fmt.Errorf("ACME HTTPS identity: %w", err)
	}
	issuer, err := pkicrypto.LoadIssuer(pkicrypto.Config{
		CertificateFile: c.IssuerFile, RootFile: c.RootFile,
		SignerFile: c.SignerFile, IdentityFile: c.IdentityFile,
	})
	if err != nil {
		return fmt.Errorf("load issuer: %w", err)
	}
	db, err := postgres.Open(ctx, c.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pki.CheckCARole(startup, db); err != nil {
		return err
	}
	deny := append([]string(nil), c.ValidationDenyNetworks...)
	for _, bind := range []netip.AddrPort{addr, statusAddr} {
		ip := bind.Addr().Unmap()
		deny = append(deny, netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	ca, err := pki.NewServer(pki.Config{
		Recipients: c.Recipients, ServerNames: c.ServerNames, ClientNames: c.ClientNames,
		Origin: c.Origin, IdentityFile: c.IdentityFile, StatusOrigin: c.StatusOrigin,
		RootCRLFile: c.RootCRLFile, RootOCSPCertificateFile: c.RootOCSPCertificateFile,
		RootOCSPSignerFile: c.RootOCSPSignerFile,
		ValidationNetworks: c.ValidationNetworks, ValidationDenyNetworks: deny,
	}, db, issuer)
	if err != nil {
		return err
	}
	if err := pki.RegisterIssuer(startup, db, issuer); err != nil {
		return errors.New("CA issuer registration failed")
	}
	if err := ca.RegisterStatus(startup, db); err != nil {
		return fmt.Errorf("register certificate status: %w", err)
	}
	rootStatus := pkicrypto.RootCRLReader{Root: issuer.Chain[0], Path: c.RootCRLFile}
	if err := rootStatus.CheckIssuer(startup, issuer.Certificate); err != nil {
		return err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr.String())
	if err != nil {
		return fmt.Errorf("bind ACME listener: %w", err)
	}
	defer listener.Close()
	statusListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", statusAddr.String())
	if err != nil {
		return fmt.Errorf("bind status listener: %w", err)
	}
	defer statusListener.Close()

	acme := newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rootStatus.CheckIssuer(r.Context(), issuer.Certificate) != nil {
			http.Error(w, "issuer unavailable", http.StatusServiceUnavailable)
			return
		}
		ca.ServeHTTP(w, r)
	}))
	status := newHTTPServer(ca.StatusHandler())
	acme.TLSConfig = loader.TLSConfig()
	done := make(chan error, 2)
	go func() { done <- acme.Serve(tls.NewListener(listener, acme.TLSConfig)) }()
	go func() { done <- status.Serve(statusListener) }()

	var runErr error
	select {
	case runErr = <-done:
		if errors.Is(runErr, http.ErrServerClosed) {
			runErr = nil
		}
	case <-ctx.Done():
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	for _, srv := range []*http.Server{acme, status} {
		if err := srv.Shutdown(shutdown); err != nil {
			runErr = errors.Join(runErr, err, srv.Close())
		}
	}
	return runErr
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}
