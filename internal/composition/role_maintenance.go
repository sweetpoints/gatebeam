package composition

import (
	"context"
	"errors"
	"gatebeam/internal/modules/certificates"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/notification"
	"gatebeam/internal/modules/pki"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// MaintainRoleSecrets runs in the owning role, with a separately authorized
// maintenance DB login for rewrap. Verification uses a read-only transaction.
func MaintainRoleSecrets(ctx context.Context, c bootstrap.Config, verify bool) (map[string]int, error) {
	if bootstrap.ValidateCapabilities(c.Mode, c) != nil {
		return nil, ErrProcessCapability
	}
	if c.Mode != "api" && c.Mode != "worker" && c.Mode != "ca" {
		return nil, errors.New("role maintenance denied")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	pool, e := postgres.Open(ctx, c)
	if e != nil {
		return nil, e
	}
	defer pool.Close()
	out := map[string]int{}
	switch c.Mode {
	case "api":
		run := identity.RewrapRoleSecrets
		if verify {
			run = identity.VerifyRoleSecrets
		}
		n, e := run(ctx, pool, c.IdentityFile, c.EncryptionRecipients.Role("api"))
		if e != nil {
			return nil, e
		}
		out["api"] = n
	case "worker":
		provider := certificates.RewrapRoleSecrets
		notice := notification.RewrapRoleSecrets
		if verify {
			provider = certificates.VerifyRoleSecrets
			notice = notification.VerifyRoleSecrets
		}
		n, e := provider(ctx, pool, c.CertificateProviderIdentityFile, c.EncryptionRecipients.Role("provider"))
		if e != nil {
			return nil, e
		}
		out["provider"] = n
		n, e = notice(ctx, pool, c.NotificationIdentityFile, c.EncryptionRecipients.Role("notification"))
		if e != nil {
			return nil, e
		}
		out["notification"] = n
	case "ca":
		run := pki.RewrapRoleSecrets
		if verify {
			run = pki.VerifyRoleSecrets
		}
		n, e := run(ctx, pool, c.CAIdentityFile, c.EncryptionRecipients.Role("ca"))
		if e != nil {
			return nil, e
		}
		out["ca"] = n
		cfg := pkicrypto.Config{IdentityFile: c.CAIdentityFile, SignerFile: c.CASignerFile, CertificateFile: c.CACertificateFile, RootFile: c.CARootFile}
		if verify {
			issuer, e := pkicrypto.LoadIssuer(cfg)
			if e != nil {
				return nil, e
			}
			if _, e = pkicrypto.LoadRootStatus(issuer, c.CARootOCSPCertificateFile, c.CARootOCSPSignerFile, c.CAIdentityFile, c.CARootCRLFile); e != nil {
				return nil, e
			}
		} else if e = pki.RewrapOnlineSigners(ctx, cfg, c.CARootOCSPSignerFile, c.EncryptionRecipients.Role("ca")); e != nil {
			return nil, e
		}
		out["online_signers"] = 2
	}
	return out, nil
}

// verifyRoleHistory is a startup and readiness gate, not an operator checkbox.
// Each owner checks its complete bounded current historical ciphertext set.
func verifyRoleHistory(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) error {
	if c.RuntimeProtocol != 1 {
		return p.Ping(ctx)
	}
	if c.NodeID != "" {
		paths := map[string]string{}
		switch c.Mode {
		case "api":
			paths["api"] = c.IdentityFile
		case "worker":
			paths["provider"] = c.CertificateProviderIdentityFile
			paths["notification"] = c.NotificationIdentityFile
		case "ca":
			paths["ca"] = c.CAIdentityFile
		}
		own := map[string]string{}
		for role, path := range paths {
			identity, e := secrets.New(path)
			if e != nil {
				return e
			}
			own[role] = identity.Recipient()
		}
		if e := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
			for role, recipient := range own {
				registered, e := deployment.NewNodes().ReadRoleRecipientWithin(sc, domain.NodeRef{ID: c.NodeID, Epoch: c.NodeEpoch}, role)
				if e != nil {
					return e
				}
				if registered != recipient {
					return errors.New("owning role identity does not match registered incarnation")
				}
			}
			return nil
		}); e != nil {
			return e
		}
	}
	switch c.Mode {
	case "api":
		_, e := identity.VerifyRoleSecrets(ctx, p, c.IdentityFile, c.EncryptionRecipients.Role("api"))
		return e
	case "worker":
		if _, e := certificates.VerifyRoleSecrets(ctx, p, c.CertificateProviderIdentityFile, c.EncryptionRecipients.Role("provider")); e != nil {
			return e
		}
		_, e := notification.VerifyRoleSecrets(ctx, p, c.NotificationIdentityFile, c.EncryptionRecipients.Role("notification"))
		return e
	case "ca":
		_, e := pki.VerifyRoleSecrets(ctx, p, c.CAIdentityFile, c.EncryptionRecipients.Role("ca"))
		return e
	}
	return errors.New("historical capability role denied")
}
