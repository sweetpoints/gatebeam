// Package application owns the immutable, server-internal deployment compiler input.
package application

type TargetRef struct {
	ID string `json:"id,omitempty"`
}

type MaterialRef struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Status   string `json:"status"`
}

type Route struct {
	Rate        *RatePolicy `json:"rate,omitempty"`
	Match       string      `json:"match"`
	Path        string      `json:"path"`
	StripPrefix bool        `json:"strip_prefix"`
	Target      TargetRef   `json:"target"`
}

type MaintenancePolicy struct {
	Enabled bool   `json:"enabled"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type CFPolicy struct {
	Mode                 string   `json:"mode"`
	TrustedProxyNetworks []string `json:"trusted_proxy_networks"`
	RequireOriginPull    bool     `json:"require_origin_pull"`
}

type ClientVerification struct {
	Mode       string       `json:"mode"`
	Trust      *MaterialRef `json:"trust,omitempty"`
	Depth      int          `json:"depth"`
	Revocation string       `json:"revocation"`
}

type AccessPolicy struct {
	Allow     []string `json:"allow"`
	Deny      []string `json:"deny"`
	DenyPaths []string `json:"deny_paths"`
}

type RatePolicy struct {
	RequestsPerSecond int `json:"requests_per_second"`
	Burst             int `json:"burst"`
	Connections       int `json:"connections"`
	Status            int `json:"status"`
}

type ConnectionPolicy struct {
	ConnectTimeoutSeconds int   `json:"connect_timeout_seconds"`
	ReadTimeoutSeconds    int   `json:"read_timeout_seconds"`
	SendTimeoutSeconds    int   `json:"send_timeout_seconds"`
	MaxBodyBytes          int64 `json:"max_body_bytes"`
	WebSocket             bool  `json:"websocket"`
	SSE                   bool  `json:"sse"`
	BufferResponses       bool  `json:"buffer_responses"`
}

type SiteConfig struct {
	Enabled            bool               `json:"enabled"`
	Domains            []string           `json:"domains"`
	DefaultTarget      TargetRef          `json:"default_target"`
	Routes             []Route            `json:"routes"`
	Maintenance        MaintenancePolicy  `json:"maintenance"`
	Cloudflare         CFPolicy           `json:"cloudflare"`
	EntryCertificate   *MaterialRef       `json:"entry_certificate,omitempty"`
	ClientVerification ClientVerification `json:"client_verification"`
	Access             AccessPolicy       `json:"access"`
	Rate               RatePolicy         `json:"rate"`
	Connection         ConnectionPolicy   `json:"connection"`
}

type TargetMember struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	TLSName string `json:"tls_name"`
}

type HealthPolicy struct {
	Enabled            bool   `json:"enabled"`
	HTTPHost           string `json:"http_host"`
	Path               string `json:"path"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
}

type TargetConfig struct {
	Name              string         `json:"name"`
	Protocol          string         `json:"protocol"`
	Members           []TargetMember `json:"members"`
	HTTPHost          string         `json:"http_host"`
	TLSServerNameMode string         `json:"tls_server_name_mode,omitempty"`
	TLSNameMode       string         `json:"tls_name_mode"`
	TLSName           string         `json:"tls_name"`
	Trust             *MaterialRef   `json:"trust,omitempty"`
	ClientCertificate *MaterialRef   `json:"client_certificate,omitempty"`
	AllowedNetworks   []string       `json:"allowed_networks"`
	Health            HealthPolicy   `json:"health"`
}

type Site struct {
	ID       string     `json:"id"`
	Revision int64      `json:"revision"`
	Config   SiteConfig `json:"config"`
}
type Target struct {
	ID       string       `json:"id"`
	Revision int64        `json:"revision"`
	Config   TargetConfig `json:"config"`
}

// Snapshot is never a public API result. It includes unchanged published sites.
type Snapshot struct {
	SourceReleaseID string   `json:"source_release_id,omitempty"`
	Version         string   `json:"version"`
	Sites           []Site   `json:"sites"`
	Targets         []Target `json:"targets"`
}
type Material struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

// MaterialRequirement binds a logical spec/trust revision to current compatible
// security state; P5 supplies actual runtime versions independently.
type MaterialRequirement struct {
	Ref   Material
	Names []string
	Usage string
}
