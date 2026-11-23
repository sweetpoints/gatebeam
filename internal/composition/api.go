package composition

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"gatebeam/internal/integration/certificateaccess"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/migration"
	"gatebeam/internal/integration/notificationaccess"
	"gatebeam/internal/integration/operationsaccess"
	"gatebeam/internal/integration/pkiaccess"
	"gatebeam/internal/integration/publication"
	backupapp "gatebeam/internal/modules/backup/application"
	backuppg "gatebeam/internal/modules/backup/infrastructure/postgres"
	"gatebeam/internal/modules/backup/infrastructure/reports"
	backupHTTP "gatebeam/internal/modules/backup/transport/http"
	"gatebeam/internal/modules/certificates"
	certapp "gatebeam/internal/modules/certificates/application"
	certHTTP "gatebeam/internal/modules/certificates/transport/http"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/deployment/application/preflight"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	deploymentpg "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/deployment/infrastructure/probe"
	releaseHTTP "gatebeam/internal/modules/deployment/transport/http"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/identity/application/auth"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/modules/ingress"
	ingressapp "gatebeam/internal/modules/ingress/application"
	ingressHTTP "gatebeam/internal/modules/ingress/transport/http"
	"gatebeam/internal/modules/notification"
	notifyapp "gatebeam/internal/modules/notification/application"
	notifyHTTP "gatebeam/internal/modules/notification/transport/http"
	obsquery "gatebeam/internal/modules/observability/application/query"
	obsHTTP "gatebeam/internal/modules/observability/transport/http"
	"gatebeam/internal/modules/pki"
	pkiapp "gatebeam/internal/modules/pki/application"
	pkistatus "gatebeam/internal/modules/pki/application/status"
	pkiHTTP "gatebeam/internal/modules/pki/transport/http"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/tlsidentity"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"
)

var ErrBootstrapDisplay = errors.New("bootstrap requires explicit local interactive display")

// Bootstrap is invoked only by the explicit interactive CLI path. No secrets are logged.
func Bootstrap(ctx context.Context, cfg bootstrap.Config) (auth.EnrollmentChallenge, error) {
	if cfg.Mode != "bootstrap" || cfg.DatabaseFile == "" || cfg.IdentityFile == "" || cfg.AdminName == "" {
		return auth.EnrollmentChallenge{}, errors.New("bootstrap configuration incomplete")
	}
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, e := postgres.Open(c, cfg)
	if e != nil {
		return auth.EnrollmentChallenge{}, e
	}
	defer p.Close()
	if e = secrets.EnsureIdentity(cfg.IdentityFile); e != nil {
		return auth.EnrollmentChallenge{}, e
	}
	se, e := secrets.ConfiguredStore(cfg.IdentityFile, cfg.EncryptionRecipients.Role("api"))
	if e != nil {
		return auth.EnrollmentChallenge{}, e
	}
	return identity.New(p, se).Bootstrap(c, cfg.AdminName)
}
func runAPI(ctx context.Context, cfg bootstrap.Config) error {
	if cfg.Environment != "development" && cfg.Environment != "production" {
		return errors.New("invalid API environment")
	}
	if cfg.Environment == "production" {
		if e := verifyManagement(ctx, cfg); e != nil {
			return e
		}
	}
	address := cfg.APIListen
	if address == "" {
		address = "127.0.0.1:8080"
	}
	if e := validateAPIListen(cfg); e != nil {
		return e
	}
	se, e := secrets.ConfiguredStore(cfg.IdentityFile, cfg.EncryptionRecipients.Role("api"))
	if e != nil {
		return e
	}
	p, e := postgres.Open(ctx, cfg)
	if e != nil {
		return e
	}
	defer p.Close()
	if e = verifyRoleHistory(ctx, cfg, p); e != nil {
		return e
	}
	protected, e := runtimeProtected(cfg)
	if e != nil && cfg.Environment == "production" {
		return e
	}
	handler, e := newAPIHandlerWithPKI(p, se, protected, cfg, authHTTP.Config{Origin: cfg.APIOrigin, Production: cfg.Environment == "production"}, func(c context.Context) error {
		if cfg.Environment == "production" {
			return verifyManagement(c, cfg)
		}
		return nil
	})
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", address)
	if e != nil {
		return errors.New("API listener unavailable")
	}
	if cfg.APITLSCertificateFile == "" {
		observeReadiness(ctx, lifecycle.Management, func(c context.Context) error { return verifyRoleHistory(c, cfg, p) })
	}
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return ctx }, Handler: roleAdmission(ctx, lifecycle.Management, withWeb(handler, os.DirFS("web/dist"))), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	if cfg.APITLSCertificateFile != "" || cfg.APITLSKeyFile != "" || cfg.APITLSTrustFile != "" {
		if len(cfg.APITLSClientNames) == 0 || len(cfg.APITLSClientNames) > 32 {
			listener.Close()
			return errors.New("API client identities required")
		}
		var fetchCRL func(context.Context) ([]byte, error)
		if cfg.CertificateStatusProfilesFile != "" {
			trust, err := os.ReadFile(cfg.APITLSTrustFile)
			if err != nil {
				listener.Close()
				return err
			}
			source, err := certificates.NewPrivateCRLSource(cfg.CertificateStatusProfilesFile, trust)
			if err != nil {
				listener.Close()
				return err
			}
			fetchCRL = source.Fetch
		}
		loader, err := tlsidentity.New(tlsidentity.Config{RenewedCertificateFile: privateTLSOutput(cfg), FetchCRL: fetchCRL, CertificateFile: cfg.APITLSCertificateFile, KeyFile: cfg.APITLSKeyFile, TrustFile: cfg.APITLSTrustFile, CRLFile: cfg.APITLSCRLFile, StateFile: cfg.APITLSStateFile, NodeID: fmt.Sprintf("%s/%d", cfg.NodeID, cfg.NodeEpoch), ClientNames: cfg.APITLSClientNames})
		if err != nil {
			listener.Close()
			return err
		}
		observeReadiness(ctx, lifecycle.Management, func(c context.Context) error {
			if e := loader.Ready(); e != nil {
				return e
			}
			return verifyRoleHistory(c, cfg, p)
		})
		listener = tls.NewListener(listener, loader.TLSConfig())
	}

	stopRenewal := startPrivateTLS(ctx, cfg, p)
	defer stopRenewal()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case e = <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return errors.New("API server failed")
	case <-ctx.Done():
		c, cancel := shutdownContext(ctx, 5*time.Second)
		defer cancel()
		e = server.Shutdown(c)
		if e != nil {
			_ = server.Close()
		}
		<-done
		return e
	}
}

// newAPIHandler is the sole live assembly: the catalog callback is set before
// accepting any request, and both applications share the same transaction runner.
func newAPIHandler(p *pgxpool.Pool, se *secrets.Store, cfg authHTTP.Config, readiness ...func(context.Context) error) (http.Handler, error) {
	return newAPIHandlerWithProtected(p, se, nil, cfg, readiness...)
}
func newAPIHandlerWithProtected(p *pgxpool.Pool, se *secrets.Store, protected []netip.Prefix, cfg authHTTP.Config, readiness ...func(context.Context) error) (http.Handler, error) {
	return newAPIHandlerWithPKI(p, se, protected, bootstrap.Config{}, cfg, readiness...)
}
func newAPIHandlerWithPKI(p *pgxpool.Pool, se *secrets.Store, protected []netip.Prefix, pkiCfg bootstrap.Config, cfg authHTTP.Config, readiness ...func(context.Context) error) (http.Handler, error) {
	if pkiCfg.CARecipient != "" && pkiCfg.CARecipient == se.Recipient() {
		return nil, errors.New("PKI EAB recipient must differ from API identity")
	}
	for _, recipient := range []string{pkiCfg.CertificateRecipient, pkiCfg.CertificateProviderRecipient} {
		if recipient != "" && (recipient == se.Recipient() || (pkiCfg.CARecipient != "" && recipient == pkiCfg.CARecipient)) {
			return nil, errors.New("certificate recipients must differ from API and CA identities")
		}
	}
	if pkiCfg.NotificationRecipient != "" {
		for _, other := range []string{se.Recipient(), pkiCfg.CARecipient, pkiCfg.CertificateRecipient, pkiCfg.CertificateProviderRecipient} {
			if pkiCfg.NotificationRecipient == other {
				return nil, errors.New("notification recipient must be dedicated")
			}
		}
	}
	catalog := &ingressaccess.Catalog{}
	auth, access := identity.NewWithCatalog(p, se, catalog)
	sites := ingress.New(p, ingressaccess.Authorizer{Identity: access})
	catalog.Ingress = sites
	materials := certificates.NewReader(p)
	materials.SetLeafStatus(certificatematerials.LeafStatus{Owner: pki.NewMaterialStatus()})
	if e := certificates.ConfigureStatus(materials, pkiCfg.CertificateStatusProfilesFile); e != nil {
		return nil, e
	}
	releases := publication.New(postgres.NewRunner(p), access, sites, certificatematerials.Adapter{Owner: materials}, deployment.New(), jobs.New(p), audit.New(), identifiers.Generator{})
	releases.SetNodes(deployment.NewNodes())
	return authHTTP.New(auth, func(ctx context.Context) error {
		for _, check := range readiness {
			if e := check(ctx); e != nil {
				return e
			}
		}
		return p.Ping(ctx)
	}, cfg, func(e *echo.Echo, cookie string) {
		e.GET("/runtime/status", func(c *echo.Context) error {
			if _, err := authHTTP.AuthenticateRequest(c, auth, cookie, false); err != nil {
				return echo.NewHTTPError(401, "authentication required")
			}
			return c.JSON(200, readRuntimeOverview(c.Request().Context(), pkiCfg))
		})
		obsHTTP.Register(e, NewStatistics(p), NewHistory(p, pkiCfg.RuntimeProtocol == 1), func(c *echo.Context, write bool) (obsquery.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, write)
			return obsquery.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
		backupHTTP.Register(e, &backupapp.Queries{Tx: postgres.NewRunner(p), Security: operationsaccess.Backup{Access: access}, Repo: backuppg.Catalog{DB: p}, Reports: reports.Store{Directory: pkiCfg.RecoveryReportDirectory}}, func(c *echo.Context) (backupapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, false)
			return backupapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
		notifyHTTP.Register(e, func(c *echo.Context, code string, write bool) (*notifyapp.Management, notifyapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, write)
			if err != nil {
				return nil, notifyapp.ActorRef{}, notifyapp.ErrDenied
			}
			security := &notificationaccess.Security{Authentication: auth, Access: access, Ingress: sites, Actor: a, Code: code}
			m, err := notification.NewManagement(p, security, pkiCfg.NotificationRecipient, pkiCfg.EncryptionRecipients.Role("notification"))
			return m, notifyapp.ActorRef{UserID: a.UserID, CredentialID: a.CredentialID, CredentialKind: string(a.CredentialKind), AuthVersion: a.AuthVersion}, err
		})
		certHTTP.Register(e, func(c *echo.Context) (*certapp.Queries, certapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, false)
			if err != nil {
				return nil, certapp.ActorRef{}, certapp.ErrDenied
			}
			security := &certificateaccess.Security{Authentication: auth, Access: access, Ingress: sites, Actor: a}
			return certificates.NewQueries(certificateaccess.QuerySecurity{Security: security, Transactions: postgres.NewRunner(p)}, certificateaccess.Graph{Ingress: sites}, certificatematerials.Active{Owner: deployment.New()}), certapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, nil
		}, func(c *echo.Context, code string) (*certapp.Management, *certapp.Service, certapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, true)
			if err != nil {
				return nil, nil, certapp.ActorRef{}, certapp.ErrDenied
			}
			security := &certificateaccess.Security{Authentication: auth, Access: access, Ingress: sites, Actor: a, Code: code}
			m, s, err := certificates.NewManagement(p, security, certificateaccess.Graph{Ingress: sites}, pkiCfg.CertificateRecipient, pkiCfg.CertificateProviderRecipient, pkiCfg.EncryptionRecipients)
			if err == nil {
				s.SetEvents(deployment.NewEvents(p))
			}
			return m, s, certapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
		pkiHTTP.RegisterQueries(e, func(c *echo.Context) (*pkiapp.Queries, pkiapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, false)
			if err != nil {
				return nil, pkiapp.ActorRef{}, err
			}
			return pki.NewQueries(p, pkiaccess.Queries{Access: access, Actor: a, Transactions: postgres.NewRunner(p)}, pkiCfg.CAOrigin), pkiapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, nil
		})
		pkiHTTP.RegisterRevocations(e, func(c *echo.Context, code string) (*pkistatus.Management, pkiapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, true)
			if err != nil {
				return nil, pkiapp.ActorRef{}, pkiapp.ErrGrantDenied
			}
			return pki.NewRevocations(p, pkiaccess.New(auth, a, code)), pkiapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, nil
		})
		pkiHTTP.RegisterGrants(e, func(c *echo.Context, code string) (*pkiapp.GrantService, pkiapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, true)
			if err != nil {
				return nil, pkiapp.ActorRef{}, pkiapp.ErrGrantDenied
			}
			service, err := pki.NewGrants(p, pkiaccess.New(auth, a, code), pkiCfg.CARecipient, pki.GrantConfig{Recipients: pkiCfg.EncryptionRecipients.Role("ca"), ServerNames: pkiCfg.CAServerNames, ClientNames: pkiCfg.CAClientNames})
			return service, pkiapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
		releaseHTTP.RegisterPreflight(e, migration.New(access, preflight.New(deploymentpg.NewRuntime(p, jobs.New(p), protected), probe.HTTP{}, protected)), func(c *echo.Context, write bool) (publication.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, write)
			return publication.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
		releaseHTTP.Register(e, releases, func(c *echo.Context, write bool) (publication.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, write)
			return publication.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
		ingressHTTP.Register(e, sites, func(c *echo.Context, write bool) (ingressapp.ActorRef, error) {
			a, err := authHTTP.AuthenticateRequest(c, auth, cookie, write)
			return ingressapp.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: string(a.CredentialKind), CredentialID: a.CredentialID}, err
		})
	})
}
