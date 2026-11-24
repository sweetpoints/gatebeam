// Package certificates assembles ordinary material capabilities, never CA signers.
package certificates

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	"gatebeam/internal/modules/certificates/infrastructure/httpchallenge"
	"gatebeam/internal/modules/certificates/infrastructure/lego"
	repo "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/modules/certificates/infrastructure/status"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"os"
	"time"
)

func NewReader(p *pgxpool.Pool) *application.Service {
	return application.New(postgres.NewRunner(p), repo.NewPublicReader(), nil, certcrypto.Crypto{}, nil, nil, nil)
}

// NewEdge loads only the leaf identity. Provider recipient is public policy used
// to reject shared-key deployment mistakes, even when key file paths differ.
func NewEdge(p *pgxpool.Pool, graph application.Graph, leafIdentityFile, providerRecipient string, policies ...secrets.RolePolicy) (*application.Service, error) {
	var policy secrets.RolePolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	leaf, e := secrets.ConfiguredStore(leafIdentityFile, policy.Role("leaf"))
	if e != nil {
		return nil, e
	}
	provider, e := secrets.NewRecipient(providerRecipient)
	if e != nil {
		return nil, e
	}
	if leaf.Recipient() == provider.Recipient() {
		return nil, errors.New("leaf and provider encryption identities must differ")
	}
	return application.New(postgres.NewRunner(p), repo.NewMaterialReader(), graph, certcrypto.Crypto{}, leaf, nil, nil), nil
}

// sealOnly has no decryption capability; a worker needs only the leaf recipient.
type sealOnly struct{ application.SecretSealer }

func (sealOnly) Open(string, []byte) ([]byte, error) {
	return nil, errors.New("leaf decryption unavailable")
}
func NewWorker(p *pgxpool.Pool, graph application.Graph, providerIdentityFile, leafRecipient, webroot string, internal ...InternalACME) (*application.Service, error) {
	var policy secrets.RolePolicy
	if len(internal) > 0 {
		policy = internal[0].Recipients
	}
	provider, e := secrets.ConfiguredStore(providerIdentityFile, policy.Role("provider"))
	if e != nil {
		return nil, e
	}
	leaf, e := secrets.ConfiguredRecipient(leafRecipient, policy.Role("leaf"))
	if e != nil {
		return nil, e
	}
	if provider.Recipient() == leaf.Recipient() {
		return nil, errors.New("leaf and provider encryption identities must differ")
	}
	client := &lego.Client{Secrets: provider, WebRoot: webroot, Journal: repo.NewChallenges(p)}
	if len(internal) > 0 {
		client.HTTPChallenges = internal[0].HTTPChallenges
	}
	if len(internal) > 0 && internal[0].Origin != "" {
		client.InternalOrigin = internal[0].Origin
		client.InternalHTTPClient = lego.HTTPClient()
		if internal[0].TransportTrustFile != "" {
			b, err := os.ReadFile(internal[0].TransportTrustFile)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(b) {
				return nil, errors.New("invalid internal ACME transport trust")
			}
			client.InternalHTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
		}
	}
	return application.New(postgres.NewRunner(p), repo.New(), graph, certcrypto.Crypto{}, sealOnly{leaf}, client, jobs.New(p)), nil
}

// NewManagement receives two public recipients and cannot open either payload.
func NewManagement(p *pgxpool.Pool, security application.Security, graph application.Graph, leafRecipient, providerRecipient string, policies ...secrets.RolePolicy) (*application.Management, *application.Service, error) {
	var policy secrets.RolePolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	leaf, e := secrets.ConfiguredRecipient(leafRecipient, policy.Role("leaf"))
	if e != nil {
		return nil, nil, e
	}
	provider, e := secrets.ConfiguredRecipient(providerRecipient, policy.Role("provider"))
	if e != nil {
		return nil, nil, e
	}
	if leaf.Recipient() == provider.Recipient() {
		return nil, nil, errors.New("leaf and provider encryption identities must differ")
	}
	management := application.NewManagement(security, graph, repo.New(), certcrypto.Crypto{}, leaf, provider, audit.New())
	service := application.New(postgres.NewRunner(p), repo.New(), graph, certcrypto.Crypto{}, nil, nil, jobs.New(p), management)
	return management, service, nil
}

// ConfigureStatus loads only operator-owned public trust/status policy. It does
// not load CA keys and never accepts request-supplied responder readiness.
func ConfigureStatus(service *application.Service, path string) error {
	if path == "" {
		return nil
	}
	profiles, err := readStatusProfiles(path)
	if err != nil {
		return err
	}
	source, err := status.New(profiles)
	if err != nil {
		return err
	}
	service.SetStatus(source)
	return nil
}

func readStatusProfiles(path string) ([]status.Profile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	var profiles []status.Profile
	if err := decoder.Decode(&profiles); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid status profiles")
	}
	return profiles, nil
}

type standardLeafStatus struct{ verifier *status.LeafVerifier }

func (s standardLeafStatus) ValidateLeafWithin(scope transaction.Scope, version application.StoredVersion, managed bool) error {
	return s.verifier.Verify(scope.Context(), version, managed, time.Now())
}

func ConfigureStandardLeafStatus(service *application.Service, profilesFile, trustFile string) error {
	profiles, err := readStatusProfiles(profilesFile)
	if err != nil {
		return err
	}
	source, err := status.New(profiles)
	if err != nil {
		return err
	}
	file, err := os.Open(trustFile)
	if err != nil {
		return err
	}
	defer file.Close()
	const limit = 1 << 20
	bundle, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(bundle) > limit {
		return status.ErrStatus
	}
	verifier, err := status.NewLeafVerifier(source, bundle)
	if err != nil {
		return err
	}
	service.SetLeafStatus(standardLeafStatus{verifier})
	return nil
}

// InternalACME is operator bootstrap policy, never a management request.
type InternalACME struct {
	Origin, TransportTrustFile string
	HTTPChallenges             lego.HTTPChallenges
	Recipients                 secrets.RolePolicy
}

func NewHTTPChallenges(p *pgxpool.Pool, nodes application.HTTPChallengeNodes) *application.HTTPChallenges {
	return application.NewHTTPChallenges(postgres.NewRunner(p), repo.NewHTTPChallenges(), nodes)
}
func NewHTTPChallengeFiles(root string) (application.HTTPChallengeFiles, error) {
	return httpchallenge.New(root)
}
func ConfigureNodeDistribution(service *application.Service, p *pgxpool.Pool, authority application.DistributionAuthority, node application.NodeRef, identityFile, recipient string) error {
	owner, e := secrets.New(identityFile)
	if e != nil {
		return e
	}
	if owner.Recipient() != recipient {
		return errors.New("leaf identity does not match registered recipient")
	}
	service.SetDistribution(application.NewDistribution(repo.NewDistribution(), authority, owner, certcrypto.Crypto{}, time.Now), node, recipient)
	return nil
}

// NewQueries cannot select encrypted columns or load any private identity.
func NewQueries(security application.Security, graph application.Graph, bindings ...application.ActiveBindings) *application.Queries {
	return application.NewQueries(security, graph, repo.NewPublicReader(), bindings...)
}
