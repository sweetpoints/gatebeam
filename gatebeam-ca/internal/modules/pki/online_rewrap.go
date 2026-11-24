package pki

import (
	"context"
	pkicrypto "gatebeam-ca/internal/modules/pki/infrastructure/crypto"
)

// RewrapOnlineSigners is controlled original-owner maintenance. The ordinary
// online CA protocol exposes no key export or recipient modification endpoint.
func RewrapOnlineSigners(ctx context.Context, cfg pkicrypto.Config, rootOCSPKey string, recipients []string) error {
	return pkicrypto.RewrapOnlineSigners(ctx, cfg, rootOCSPKey, recipients)
}
