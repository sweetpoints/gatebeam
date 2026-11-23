package composition

import (
	"context"
	"errors"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"path/filepath"
)

// PrepareRoleIdentity creates only the invoking node's owning role identities.
// Existing standard age identities are retained. Only public recipients return.
func PrepareRoleIdentity(ctx context.Context, c bootstrap.Config) (map[string]string, error) {
	if c.RuntimeProtocol != 1 || bootstrap.ValidateCapabilities(c.Mode, c) != nil {
		return nil, ErrProcessCapability
	}
	paths := map[string]string{}
	switch c.Mode {
	case "api":
		paths["api"] = c.IdentityFile
	case "worker":
		paths["provider"] = c.CertificateProviderIdentityFile
		paths["notification"] = c.NotificationIdentityFile
	case "edge":
		paths["leaf"] = c.CertificateIdentityFile
	case "ca":
		paths["ca"] = c.CAIdentityFile
	default:
		return nil, ErrProcessCapability
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return nil, errors.New("canonical independent role identity files required")
		}
		seen[path] = true
	}
	out := map[string]string{}
	for role, path := range paths {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if e := secrets.EnsureIdentity(path); e != nil {
			return nil, e
		}
		store, e := secrets.New(path)
		if e != nil {
			return nil, e
		}
		out[role] = store.Recipient()
	}
	return out, nil
}
