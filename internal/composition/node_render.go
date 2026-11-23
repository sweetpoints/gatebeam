package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type NodeRenderRequest struct {
	Node               domain.NodeDeployment `json:"node"`
	PeerNode           domain.NodeDeployment `json:"peer_node"`
	TemplatesDirectory string                `json:"templates_directory"`
	OutputDirectory    string                `json:"output_directory"`
	Recipients         secrets.RolePolicy    `json:"recipients"`
	NodeRecipients     map[string]string     `json:"node_recipients"`
	BackupRecipient    string                `json:"backup_recipient,omitempty"`
	BackupEpoch        string                `json:"backup_epoch,omitempty"`
}

// RenderNodeConfigs only creates a fresh protected configuration tree. It never
// copies identities, opens DB secrets or overwrites an initialized node.
func RenderNodeConfigs(ctx context.Context, r NodeRenderRequest) error {
	if r.Node.Validate() != nil || r.PeerNode.Validate() != nil || r.Node.Node.ID == r.PeerNode.Node.ID || r.Node.PrivateAddress != r.PeerNode.PeerAddress || r.Node.PeerAddress != r.PeerNode.PrivateAddress || r.Node.EnvironmentFile != r.OutputDirectory+".env" || secrets.ValidateRoleRecipients(r.Recipients) != nil || !filepath.IsAbs(r.OutputDirectory) || filepath.Clean(r.OutputDirectory) != r.OutputDirectory {
		return errors.New("invalid protected render inputs")
	}
	for _, role := range []string{"api", "provider", "notification", "ca", "leaf"} {
		if len(r.Recipients[role]) < 2 || !slices.Contains(r.Recipients[role], r.NodeRecipients[role]) {
			return errors.New("independent own recipient required for every role")
		}
	}
	if r.BackupRecipient != "" {
		if _, e := secrets.NewRecipient(r.BackupRecipient); e != nil || r.BackupEpoch == "" {
			return errors.New("offline backup recipient/epoch required")
		}
		for _, public := range r.Recipients {
			if slices.Contains(public, r.BackupRecipient) {
				return errors.New("recovery recipient must be offline")
			}
		}
	}
	type roleTemplate struct{ mode, path, ip string }
	templates := map[string]roleTemplate{"nginx": {"edge", "edge/edge.example.json", "172.31.0.2"}, "management": {"api", "edge/api.example.json", "172.31.0.3"}, "background-jobs": {"worker", "edge/worker.example.json", "172.31.0.5"}, "internal-ca": {"ca", "pki/ca.example.json", "172.31.0.6"}, "log-query": {"query", "query/query.example.json", "172.29.0.2"}}
	configs := map[string][]byte{}
	health := map[string]map[string]string{}
	for _, node := range []domain.NodeDeployment{r.Node, r.PeerNode} {
		health[node.Node.ID] = map[string]string{}
		for role, value := range node.Roles {
			health[node.Node.ID][role] = "http://" + net.JoinHostPort(node.PrivateAddress, fmt.Sprint(value.HealthPort))
		}
	}
	hostPrefix := func(raw string) string {
		addr, _ := netip.ParseAddr(raw)
		return netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	for _, name := range domain.NodeRoleNames() {
		if e := ctx.Err(); e != nil {
			return e
		}
		template := templates[name]
		role := r.Node.Roles[name]
		if role.ConfigFile != filepath.Join(r.OutputDirectory, template.mode, template.mode+".json") {
			return errors.New("manifest/config output binding mismatch")
		}
		var c bootstrap.Config
		if e := input(filepath.Join(r.TemplatesDirectory, template.path), &c); e != nil {
			return e
		}
		c.Mode = template.mode
		c.NodeID = r.Node.Node.ID
		c.NodeEpoch = r.Node.Node.Epoch
		c.RuntimeProtocol = role.Protocol
		c.ImageDigest = strings.Split(role.Image, "@")[1]
		c.HealthListen = template.ip + ":9090"
		c.ControlSocket = "/run/control/control.sock"
		c.DrainSeconds = 60
		c.EncryptionRecipients = r.Recipients
		c.CertificateRecipient = r.NodeRecipients["leaf"]
		c.CertificateProviderRecipient = r.NodeRecipients["provider"]
		c.NotificationRecipient = r.NodeRecipients["notification"]
		c.CARecipient = r.NodeRecipients["ca"]
		switch name {
		case "nginx":
			c.ManagementAPIAddress = net.JoinHostPort(r.Node.PrivateAddress, "9443")
			c.ManagementAPIPeerAddress = net.JoinHostPort(r.Node.PeerAddress, "9443")
		case "management":
			c.HealthEndpoints = health
			c.ManagementAddress = net.JoinHostPort(r.Node.PrivateAddress, "443")
		case "background-jobs":
			c.BackupSpoolDirectory = "/var/lib/gatebeam/backups"
			c.ManagementAPIAddress = net.JoinHostPort(r.Node.PrivateAddress, "9443")
		case "log-query":
			c.CertificateRecipient = ""
			c.CertificateProviderRecipient = ""
			c.NotificationRecipient = ""
			c.CARecipient = ""
		}
		if name != "log-query" {
			c.ProtectedNetworks = []string{hostPrefix(r.Node.PrivateAddress), hostPrefix(r.Node.PeerAddress)}
			c.BackupRecipient = r.BackupRecipient
			c.BackupEpoch = r.BackupEpoch
			if r.BackupRecipient != "" {
				c.BackupCapsuleDirectory = "/var/lib/gatebeam/capsules"
			}
		}
		if bootstrap.ValidateCapabilities(c.Mode, c) != nil {
			return ErrProcessCapability
		}
		data, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		configs[template.mode] = append(data, '\n')
	}
	if _, e := os.Lstat(r.Node.EnvironmentFile); !os.IsNotExist(e) {
		return errors.New("existing node environment cannot be overwritten")
	}
	if e := os.Mkdir(r.OutputDirectory, 0700); e != nil {
		return e
	}
	for mode, data := range configs {
		dir := filepath.Join(r.OutputDirectory, mode)
		if e := os.Mkdir(dir, 0700); e != nil {
			return e
		}
		file := filepath.Join(dir, mode+".json")
		if e := writeNewNodeFile(file, data); e != nil {
			return e
		}
		if e := syncNodeDirectory(dir); e != nil {
			return e
		}
		if os.Geteuid() == 0 {
			if e := os.Chown(file, 101, 101); e != nil {
				return e
			}
			if e := os.Chown(dir, 101, 101); e != nil {
				return e
			}
		}
	}
	if os.Geteuid() == 0 {
		if e := os.Chown(r.OutputDirectory, 101, 101); e != nil {
			return e
		}
	}
	var env strings.Builder
	privateBind := r.Node.PrivateAddress
	if strings.Contains(privateBind, ":") {
		privateBind = "[" + privateBind + "]"
	}
	fmt.Fprintf(&env, "COMPOSE_PROJECT_NAME=%s\nNODE_STORAGE_PREFIX=%s\nNODE_PRIVATE_ADDRESS=%s\nGATEBEAM_SECRET_ROOT=%s\nEDGE_BIND=0.0.0.0\n", r.Node.StoragePrefix, r.Node.StoragePrefix, privateBind, r.OutputDirectory)
	names := map[string]string{"nginx": "NGINX", "management": "MANAGEMENT", "background-jobs": "JOBS", "internal-ca": "CA", "log-query": "LOG_QUERY"}
	for _, name := range domain.NodeRoleNames() {
		role := r.Node.Roles[name]
		fmt.Fprintf(&env, "GATEBEAM_%s_IMAGE=%s\nGATEBEAM_%s_HEALTH_PORT=%d\n", names[name], role.Image, names[name], role.HealthPort)
	}
	if e := syncNodeDirectory(r.OutputDirectory); e != nil {
		return e
	}
	if e := writeNewNodeFile(r.Node.EnvironmentFile, []byte(env.String())); e != nil {
		return e
	}
	return syncNodeDirectory(filepath.Dir(r.OutputDirectory))
}

func writeNewNodeFile(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func syncNodeDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
