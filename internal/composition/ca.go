package composition

import (
	"context"
	"crypto/tls"
	"errors"
	"gatebeam/internal/modules/pki"
	"gatebeam/internal/modules/pki/application"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/tlsidentity"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func importCA(ctx context.Context, cfg bootstrap.Config) error {
	return pki.ImportOffline(ctx, application.ImportCommand{SourceDirectory: cfg.CAImportDirectory, OnlineDirectory: cfg.CAOutputDirectory})
}
func bootstrapCA(ctx context.Context, cfg bootstrap.Config) error {
	if cfg.CAStatusOrigin == "" {
		return errors.New("offline ceremony requires the canonical HTTP status origin")
	}
	return pki.BootstrapOffline(ctx, application.BootstrapCommand{RootDirectory: cfg.OfflineRootDirectory, OnlineDirectory: cfg.CAOutputDirectory, RootName: cfg.CARootName, IntermediateName: cfg.CAIntermediateName, StatusOrigin: cfg.CAStatusOrigin})
}
func validateCAConfig(cfg bootstrap.Config) error {
	addr, e := netip.ParseAddrPort(cfg.CAListen)
	if e != nil || addr.Port() == 0 || (!addr.Addr().IsPrivate() && !addr.Addr().IsLoopback()) || cfg.CAHostname == "" || cfg.CATLSCertificateFile == "" || cfg.CATLSKeyFile == "" || cfg.CACertificateFile == "" || cfg.CARootFile == "" || cfg.CASignerFile == "" || cfg.CAIdentityFile == "" || cfg.DatabaseFile == "" {
		return errors.New("CA requires explicit private listener, TLS, database and issuer configuration")
	}
	statusAddr, e := netip.ParseAddrPort(cfg.CAStatusListen)
	if e != nil || statusAddr.Port() == 0 || (!statusAddr.Addr().IsPrivate() && !statusAddr.Addr().IsLoopback()) || cfg.CAStatusOrigin == "" || cfg.CARootCRLFile == "" {
		return errors.New("CA requires separate private HTTP status listener and public root CRL")
	}
	return nil
}
func runCA(ctx context.Context, cfg bootstrap.Config) error {
	if e := validateCAConfig(cfg); e != nil {
		return e
	}
	issuer, e := pkicrypto.LoadIssuer(pkicrypto.Config{CertificateFile: cfg.CACertificateFile, RootFile: cfg.CARootFile, SignerFile: cfg.CASignerFile, IdentityFile: cfg.CAIdentityFile})
	if e != nil {
		return e
	}

	db, e := postgres.Open(ctx, cfg)
	if e != nil {
		return e
	}
	defer db.Close()
	if e = verifyRoleHistory(ctx, cfg, db); e != nil {
		return e
	}
	addr, _ := netip.ParseAddrPort(cfg.CAListen)
	deny := append([]string(nil), cfg.CAValidationDenyNetworks...)
	deny = append(deny, netip.PrefixFrom(addr.Addr(), addr.Addr().BitLen()).String())
	statusAddr, _ := netip.ParseAddrPort(cfg.CAStatusListen)
	deny = append(deny, netip.PrefixFrom(statusAddr.Addr(), statusAddr.Addr().BitLen()).String())
	server, e := pki.NewServer(pki.Config{Recipients: cfg.EncryptionRecipients.Role("ca"), ServerNames: cfg.CAServerNames, ClientNames: cfg.CAClientNames, Origin: cfg.CAOrigin, IdentityFile: cfg.CAIdentityFile, StatusOrigin: cfg.CAStatusOrigin, RootCRLFile: cfg.CARootCRLFile, RootOCSPCertificateFile: cfg.CARootOCSPCertificateFile, RootOCSPSignerFile: cfg.CARootOCSPSignerFile, ValidationNetworks: cfg.CAValidationNetworks, ValidationDenyNetworks: deny}, db, issuer)
	if e != nil {
		return e
	}
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e = pki.CheckCARole(startup, db); e != nil {
		return e
	}
	if e = pki.RegisterIssuer(startup, db, issuer); e != nil {
		return errors.New("CA issuer registration failed")
	}
	if e = server.RegisterStatus(startup, db); e != nil {
		return e
	}
	// Validate offline status before exposing either protocol listener.
	if e = (pkicrypto.RootCRLReader{Root: issuer.Chain[0], Path: cfg.CARootCRLFile}).CheckIssuer(ctx, issuer.Certificate); e != nil {
		return e
	}
	loader, e := tlsidentity.New(tlsidentity.Config{RenewedCertificateFile: privateTLSOutput(cfg), CertificateFile: cfg.CATLSCertificateFile, KeyFile: cfg.CATLSKeyFile, TrustFile: cfg.CARootFile, ServerName: cfg.CAHostname})
	if e != nil {
		return e
	}
	tlsCfg := loader.TLSConfig()
	listener, e := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.CAListen)
	if e != nil {
		return errors.New("CA private listener unavailable")
	}
	defer listener.Close()
	statusListener, e := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.CAStatusListen)
	if e != nil {
		return errors.New("CA private status listener unavailable")
	}
	defer statusListener.Close()
	makeServer := func(handler http.Handler) *http.Server {
		return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	}
	observeReadiness(ctx, lifecycle.ACME, func(c context.Context) error {
		if e := verifyRoleHistory(c, cfg, db); e != nil {
			return e
		}
		if e := loader.Ready(); e != nil {
			return e
		}
		return issuer.Validate(time.Now())
	})
	observeReadiness(ctx, lifecycle.Status, func(c context.Context) error {
		if e := verifyRoleHistory(c, cfg, db); e != nil {
			return e
		}
		return (pkicrypto.RootCRLReader{Root: issuer.Chain[0], Path: cfg.CARootCRLFile}).CheckIssuer(c, issuer.Certificate)
	})
	srv, statusSrv := makeServer(roleAdmission(ctx, lifecycle.ACME, server)), makeServer(roleAdmission(ctx, lifecycle.Status, server.StatusHandler()))
	srv.BaseContext = func(net.Listener) context.Context { return ctx }
	statusSrv.BaseContext = srv.BaseContext
	stopRenewal := startPrivateTLS(ctx, cfg, db)
	defer stopRenewal()
	done := make(chan error, 2)
	go func() { done <- srv.Serve(tls.NewListener(listener, tlsCfg)) }()
	go func() { done <- statusSrv.Serve(statusListener) }()
	select {
	case e = <-done:
	case <-ctx.Done():
		e = nil
	}
	shutdown, cancelShutdown := shutdownContext(ctx, 5*time.Second)
	defer cancelShutdown()
	for _, s := range []*http.Server{srv, statusSrv} {
		if err := s.Shutdown(shutdown); err != nil {
			_ = s.Close()
			if e == nil {
				e = err
			}
		}
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
