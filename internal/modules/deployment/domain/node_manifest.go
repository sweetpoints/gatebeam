package domain

import (
	"net/netip"
	"path"
	"regexp"
	"strings"
)

// NodeDeployment is protected operator inventory, never an HTTP-editable draft.
type NodeDeployment struct {
	CanaryFile      string                    `json:"canary_file,omitempty"`
	Node            NodeRef                   `json:"node"`
	PrivateAddress  string                    `json:"private_address"`
	PeerAddress     string                    `json:"peer_address"`
	Instance        string                    `json:"instance"`
	InstanceGroup   string                    `json:"instance_group"`
	PublicBackend   string                    `json:"public_backend"`
	PrivateBackend  string                    `json:"private_backend"`
	ComposeFile     string                    `json:"compose_file"`
	EnvironmentFile string                    `json:"environment_file"`
	StoragePrefix   string                    `json:"storage_prefix"`
	Roles           map[string]RoleDeployment `json:"roles"`
}
type RoleDeployment struct {
	Image         string `json:"image"`
	Protocol      uint32 `json:"protocol"`
	ConfigFile    string `json:"config_file"`
	HealthPort    int    `json:"health_port"`
	ControlVolume string `json:"control_volume"`
}

var fixedImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}$`)
var instanceRef = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{0,62}/zones/[a-z0-9-]+/instances/[a-z][a-z0-9-]{0,62}$`)
var groupRef = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{0,62}/zones/[a-z0-9-]+/instanceGroups/[a-z][a-z0-9-]{0,62}$`)
var backendRef = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{0,62}/regions/[a-z0-9-]+/backendServices/[a-z][a-z0-9-]{0,62}$`)
var storageName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,80}$`)

var operatorPath = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+$`)

func operatorFile(s string) bool {
	return operatorPath.MatchString(s) && path.Clean(s) == s && s != "/" && !strings.ContainsAny(s, "\x00\r\n\t ")
}
func NodeRoleNames() []string {
	return []string{"nginx", "management", "background-jobs", "internal-ca", "log-query"}
}
func (n NodeDeployment) Validate() error {
	if n.CanaryFile != "" && !operatorFile(n.CanaryFile) {
		return ErrInvalid
	}
	own, e := netip.ParseAddr(n.PrivateAddress)
	peer, pe := netip.ParseAddr(n.PeerAddress)
	if !n.Node.Valid() || e != nil || pe != nil || !own.IsPrivate() || !peer.IsPrivate() || own == peer || !instanceRef.MatchString(n.Instance) || !groupRef.MatchString(n.InstanceGroup) || !backendRef.MatchString(n.PublicBackend) || !backendRef.MatchString(n.PrivateBackend) || !operatorFile(n.ComposeFile) || !operatorFile(n.EnvironmentFile) || !storageName.MatchString(n.StoragePrefix) || len(n.Roles) != 5 {
		return ErrInvalid
	}
	ports := map[int]bool{}
	configs := map[string]bool{}
	volumes := map[string]bool{}
	for _, name := range NodeRoleNames() {
		r, ok := n.Roles[name]
		if !ok || !fixedImage.MatchString(r.Image) || r.Protocol != 1 || !operatorFile(r.ConfigFile) || r.HealthPort < 1024 || r.HealthPort > 65535 || ports[r.HealthPort] || configs[r.ConfigFile] || !storageName.MatchString(r.ControlVolume) || r.ControlVolume != n.StoragePrefix+"-"+name+"-control" || volumes[r.ControlVolume] {
			return ErrInvalid
		}
		ports[r.HealthPort] = true
		configs[r.ConfigFile] = true
		volumes[r.ControlVolume] = true
	}
	return nil
}

func ValidInstanceReference(s string) bool { return instanceRef.MatchString(s) }
