// Package runtime owns server-internal compilation ports. No public request may
// supply RuntimeState: trusted workers bind immutable generations to revisions.
package runtime

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/domain"
	"net/netip"
	"time"
)

type Artifact struct {
	// CertificateRefs are fresh public immutable refs selected exactly where
	// native TLS directives are emitted. They contain no material bytes.
	CertificateRefs []app.Material
	ID              string
	Files           map[string][]byte
	Digest          string
}
type Compiler interface {
	Compile(app.Snapshot, RuntimeState) (Artifact, error)
}
type Resolver interface {
	Resolve(context.Context, string) ([]netip.Addr, error)
}
type Resolution struct {
	TargetRevision int64
	Addresses      []netip.Addr
}
type Health struct {
	TargetRevision int64
	Unhealthy      map[string]bool
}
type Material struct {
	VersionID, Digest                        string // public certificate metadata confirmed only at final native apply
	Revision                                 int64
	CertificatePEM, KeyPEM, TrustPEM, CRLPEM []byte
	OriginPullAuthorized                     bool // trusted provider approval of official CF CA or operator custom AOP policy
	OCSP                                     *OCSPState
}
type CloudflareSet struct {
	ValidUntil time.Time
	Generation string
	Networks   []netip.Prefix
}
type RuntimeState struct {
	OCSPResponder                                                                string // fixed loopback standard HTTP responder owned by this supervisor
	ManagementACMEWebRoot, ManagementACMEHost                                    string
	ACMEWebRoot                                                                  string // process-owned shared HTTP-01 challenge directory
	LogDirectory                                                                 string // fixed process-owned durable directory, never supplied by API
	Management                                                                   *ManagementTLS
	Generation                                                                   string
	DNSGeneration, HealthGeneration, CertificateGeneration, RevocationGeneration string
	Now                                                                          time.Time
	Resolved                                                                     map[string]Resolution // target ID + "/" + configured member address
	Health                                                                       map[string]Health
	Materials                                                                    map[string]Material // authorized immutable material ID, revision checked
	Cloudflare                                                                   CloudflareSet       // official authenticated source; draft values only narrow
	OCSPResolver                                                                 *ResolverState
	TLSHandshakeTimeoutSeconds                                                   int            // whole native TLS/OCSP client_header_timeout budget
	ProtectedNetworks                                                            []netip.Prefix // control/API/CA/metadata service addresses
}

// OCSPState is trusted provider readiness for CA-issued client certificate AIA
// names. The material provider owns the issuing policy and binds these names
// to the AIA URLs it authorizes; Nginx uses the certificate's standard AIA.
// ResolverState points only to the server-owned DNS service constrained to those
// names and approved responder networks. It is never a public API override.
type OCSPState struct {
	Generation     string
	ValidUntil     time.Time
	ResponderNames []string
}
type ResolverState struct {
	Generation                      string
	Servers                         []netip.AddrPort
	TimeoutSeconds, ValidForSeconds int
}

// Plan binds logical configuration to one freshly resolved security/runtime
// generation. Generation changes invalidate staging at the final authority check.
type Plan struct {
	Snapshot app.Snapshot
	Runtime  RuntimeState
}
type Process interface {
	Validate(context.Context, string) error
	Activate(context.Context, string) error
	Observe(context.Context) (string, error)
	RotateLogs(context.Context) error
	Stop(context.Context) error
}
type ArtifactStore interface {
	Lock(context.Context) (func(), error)
	Stage(context.Context, Artifact) (string, error)
	Switch(context.Context, string) error
}
type Journal interface {
	Load(context.Context) (domain.ApplyJournal, error)
	Save(context.Context, domain.ApplyJournal) error
}

// PublicationAuthority is bound to a claimed lease at composition time. Within
// rechecks the trusted first publisher, current graph, lease and staged security
// generations, then executes only the bounded final native effect and commits
// owner publication + release + job receipt in the same Scope. OS writes remain
// outside DB atomicity even while authorization locks are held.
type PublicationAuthority interface {
	ActivateWithin(context.Context, string, Plan, func() error) error
	Prepare(context.Context, string) (Plan, error)
	Within(context.Context, string, Plan, func() error) error
	CurrentVerified(context.Context) (Plan, error)
	// The effect must use this exact final-authority context, including time
	// already consumed acquiring locks and validating current security.
	RestoreActivateWithin(context.Context, Plan, func(context.Context) error) error
	WithRestore(context.Context, Plan, func(context.Context) error) error
	Confirmed(context.Context, domain.ApplyJournal) (bool, error)
}

// ManagementTLS is a manually provisioned bootstrap certificate and fixed API
// endpoint, independent from site materials and the later P5 ACME lifecycle.
type ManagementUpstreamTLS struct {
	ServerName                       string
	TrustPEM, CertificatePEM, KeyPEM []byte
}
type ManagementTLS struct {
	AdditionalAPIAddresses           []netip.AddrPort `json:",omitempty"`
	UnavailableAPIAddresses          []netip.AddrPort `json:",omitempty"`
	ConfigurationDigest              string
	PeerAPIAddress                   netip.AddrPort
	APIUnavailable, PeerUnavailable  bool
	UpstreamTLS                      *ManagementUpstreamTLS
	Domain                           string
	APIAddress                       netip.AddrPort
	CertificatePEM, KeyPEM, TrustPEM []byte
}
