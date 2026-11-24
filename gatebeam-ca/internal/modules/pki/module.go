// Package pki assembles separate management and CA capabilities. Only composition
// imports this package; management never receives a signer or secret loader.
package pki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"gatebeam-ca/internal/modules/pki/application"
	accountapp "gatebeam-ca/internal/modules/pki/application/acme"
	statusapp "gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	pkicrypto "gatebeam-ca/internal/modules/pki/infrastructure/crypto"
	"gatebeam-ca/internal/modules/pki/infrastructure/http01"
	josecrypto "gatebeam-ca/internal/modules/pki/infrastructure/jose"
	pkipg "gatebeam-ca/internal/modules/pki/infrastructure/postgres"
	"gatebeam-ca/internal/modules/pki/transport/acme"
	crltransport "gatebeam-ca/internal/modules/pki/transport/crl"
	ocsptransport "gatebeam-ca/internal/modules/pki/transport/ocsp"
	"gatebeam-ca/internal/platform/audit"
	platformpg "gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/secrets"
	"gatebeam-ca/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/url"
	"slices"
	"time"
)

type Config struct {
	Recipients                                  []string
	ServerNames, ClientNames                    []string
	ValidationNetworks, ValidationDenyNetworks  []string
	Origin, IdentityFile                        string
	RootOCSPCertificateFile, RootOCSPSignerFile string
	StatusOrigin, RootCRLFile                   string
}
type Server struct {
	handler     http.Handler
	status      http.Handler
	root        *pkicrypto.RootStatus
	rootService *statusapp.RootService
}

func (s *Server) StatusHandler() http.Handler { return s.status }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }
func NewServer(cfg Config, db *pgxpool.Pool, issuer pkicrypto.Issuer) (*Server, error) {
	if db == nil {
		return nil, errors.New("CA database required")
	}
	if e := issuer.Validate(time.Now()); e != nil {
		return nil, e
	}
	if _, e := domain.NewPolicy(cfg.ServerNames, domain.ServerAuth); e != nil {
		return nil, e
	}
	if _, e := domain.NewPolicy(cfg.ClientNames, domain.ClientAuth); e != nil {
		return nil, e
	}
	if cfg.Origin == "" || cfg.IdentityFile == "" {
		return nil, errors.New("CA ACME origin and identity required")
	}
	secret, e := secrets.ConfiguredStore(cfg.IdentityFile, cfg.Recipients)
	if e != nil {
		return nil, e
	}
	u, err := url.Parse(cfg.StatusOrigin)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("CA requires canonical HTTP status origin")
	}
	issuer.StatusOrigin = cfg.StatusOrigin
	tx := platformpg.NewRunner(db)
	repo := pkipg.New()
	validator, e := http01.New(cfg.ValidationNetworks, cfg.ValidationDenyNetworks)
	if e != nil {
		return nil, e
	}
	orders := accountapp.NewOrders(tx, repo, pkicrypto.Random{}, validator, pkicrypto.OrderSigner{Issuer: issuer, Policies: issuerPolicies(cfg)}, nil)
	protocol, e := acme.NewProtocol(cfg.Origin, accountapp.New(tx, repo, pkicrypto.Random{}, secret, nil), accountapp.NewNonces(tx, repo, pkicrypto.Random{}, nil), josecrypto.Crypto{}, orders)
	if e != nil {
		return nil, e
	}
	if !slices.Equal(issuer.Certificate.OCSPServer, []string{cfg.StatusOrigin + "/ocsp"}) {
		return nil, errors.New("intermediate requires configured standard OCSP AIA from offline ceremony")
	}
	root, e := pkicrypto.LoadRootStatus(issuer, cfg.RootOCSPCertificateFile, cfg.RootOCSPSignerFile, cfg.IdentityFile, cfg.RootCRLFile)
	if e != nil {
		return nil, e
	}
	statusService := statusapp.New(tx, repo, pkicrypto.NewStatusSigner(issuer), nil)
	protocol.SetRevocations(statusService)
	mux := http.NewServeMux()
	rootService := statusapp.NewRoot(tx, repo, root)
	ocspHandler := ocsptransport.New(statusapp.Responders{Leaf: statusService, Root: rootService})
	mux.Handle("/ocsp", ocspHandler)
	mux.Handle("/ocsp/", ocspHandler)
	mux.Handle("/crl/", crltransport.New(statusService))
	mux.Handle("/crl/root.der", crltransport.NewRoot(rootService))
	return &Server{handler: protocol, status: mux, root: root, rootService: rootService}, nil
}
func ImportOffline(ctx context.Context, c application.ImportCommand) error {
	return application.Import(ctx, pkicrypto.Importer{}, c)
}
func BootstrapOffline(ctx context.Context, c application.BootstrapCommand) error {
	return application.Bootstrap(ctx, pkicrypto.Bootstrapper{}, c)
}
func RegisterIssuer(ctx context.Context, db *pgxpool.Pool, issuer pkicrypto.Issuer) error {
	if e := issuer.Validate(time.Now()); e != nil {
		return e
	}
	return application.NewRegistry(platformpg.NewRunner(db), pkipg.New()).Register(ctx, issuer.Metadata(), issuer.Certificate.Raw)
}
func NewManagement(db *pgxpool.Pool) *application.Management {
	return application.NewManagement(pkipg.NewReader(db))
}
func CheckCARole(ctx context.Context, db *pgxpool.Pool) error { return pkipg.CheckCARole(ctx, db) }

// NewGrants composes API-only enrollment management with a public age recipient.
// No private CA identity, issuer, signing key or decryptor is accepted here.
type GrantConfig struct{ ServerNames, ClientNames, Recipients []string }

func NewGrants(db *pgxpool.Pool, security application.SecurityAction, recipient string, cfg GrantConfig) (*application.GrantService, error) {
	se, e := secrets.ConfiguredRecipient(recipient, cfg.Recipients)
	if e != nil {
		return nil, e
	}
	server, e := domain.NewPolicy(cfg.ServerNames, domain.ServerAuth)
	if e != nil {
		return nil, e
	}
	client, e := domain.NewPolicy(cfg.ClientNames, domain.ClientAuth)
	if e != nil {
		return nil, e
	}
	return application.NewGrantService(security, pkipg.New(), se, pkicrypto.Random{}, audit.New(), map[string]domain.Policy{"server": server, "client": client}, nil), nil
}

func issuerPolicies(cfg Config) map[domain.Usage]domain.Policy {
	server, _ := domain.NewPolicy(cfg.ServerNames, domain.ServerAuth)
	client, _ := domain.NewPolicy(cfg.ClientNames, domain.ClientAuth)
	return map[domain.Usage]domain.Policy{domain.ServerAuth: server, domain.ClientAuth: client}
}

// NewRevocations composes only authoritative management state and audit.
func NewRevocations(db *pgxpool.Pool, security application.SecurityAction) *statusapp.Management {
	return statusapp.NewManagement(security, pkipg.New(), audit.New(), pkicrypto.Random{}, nil)
}

// RegisterStatus records only offline-authorized public root/delegate/issuer
// certificates and reserves their root-qualified serials before serving status.
func (s *Server) RegisterStatus(ctx context.Context, db *pgxpool.Pool) error {
	tx := platformpg.NewRunner(db)
	repo := pkipg.New()
	root := s.root
	if e := application.NewRegistry(tx, repo).Register(ctx, root.RootMetadata(), root.Root.Raw); e != nil {
		return e
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		for _, cert := range []*x509.Certificate{root.Intermediate, root.Credential} {
			if e := repo.ReserveResponder(sc, root.RootMetadata().ID, domain.Serial(fmt.Sprintf("%040x", cert.SerialNumber)), cert.Raw); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		return e
	}
	_, e := s.rootService.ReadRootCRL(ctx)
	return e
}

// NewQueries receives only current read authority and fixed public directories.
func NewQueries(db *pgxpool.Pool, security application.SecurityAction, origin string) *application.Queries {
	directories := map[string]string{}
	u, e := url.Parse(origin)
	if e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" {
		for _, kind := range []string{"server", "client"} {
			directories[kind] = origin + "/acme/" + kind + "/directory"
		}
	}
	return application.NewQueries(security, pkipg.New(), directories)
}

// NewMaterialStatus exposes only current public status, with no signer.
func NewMaterialStatus() *statusapp.Materials { return statusapp.NewMaterials(pkipg.New()) }
