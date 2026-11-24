package pkicrypto

import (
	"context"
	"crypto/x509"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/platform/secrets"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Importer struct{}

// Import accepts an offline root's already signed intermediate and OCSP
// delegate, standard PKCS8 keys, public root and signed DER CRL. It never reads
// a root key or contacts a network, and only publishes a validated fresh epoch.
func (Importer) Import(ctx context.Context, c application.ImportCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source, err := filepath.EvalSymlinks(c.SourceDirectory)
	if err != nil || !filepath.IsAbs(source) {
		return ErrIssuer
	}
	output, err := newPath(c.OnlineDirectory)
	if err != nil || output == source || strings.HasPrefix(output, source+string(os.PathSeparator)) || strings.HasPrefix(source, output+string(os.PathSeparator)) {
		return ErrIssuer
	}
	files := map[string][]byte{}
	for _, name := range []string{"issuer.pem", "root.pem", "root-ocsp.pem", "root.crl.der", "issuer-key.pem", "root-ocsp-key.pem"} {
		data, err := readFile(filepath.Join(source, name), strings.HasSuffix(name, "-key.pem"))
		if err != nil {
			return err
		}
		files[name] = data
	}
	defer clear(files["issuer-key.pem"])
	defer clear(files["root-ocsp-key.pem"])
	cert, err := parseCertificate(files["issuer.pem"])
	if err != nil {
		return err
	}
	root, err := parseCertificate(files["root.pem"])
	if err != nil {
		return err
	}
	signer, err := parseKey(files["issuer-key.pem"])
	if err != nil {
		return err
	}
	issuer := Issuer{Certificate: cert, Chain: []*x509.Certificate{root}, Signer: signer}
	if err = issuer.Validate(time.Now()); err != nil {
		return err
	}
	delegate, err := parseCertificate(files["root-ocsp.pem"])
	if err != nil {
		return err
	}
	delegateKey, err := parseKey(files["root-ocsp-key.pem"])
	if err != nil {
		return err
	}
	crl := RootCRLReader{Root: root, Path: filepath.Join(source, "root.crl.der")}
	status := RootStatus{Root: root, Intermediate: cert, Credential: delegate, key: delegateKey, CRL: crl}
	if err = status.Validate(time.Now()); err != nil {
		return err
	}
	if err = crl.CheckIssuer(ctx, cert); err != nil {
		return err
	}
	if err = crl.CheckIssuer(ctx, delegate); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".ca-import-")
	if err != nil {
		return ErrIssuer
	}
	defer os.RemoveAll(stage)
	identity := filepath.Join(stage, "identity.agekey")
	if err = secrets.EnsureIdentity(identity); err != nil {
		return err
	}
	store, err := secrets.New(identity)
	if err != nil {
		return err
	}
	for name, label := range map[string]string{"issuer": "pki-online-issuer", "root-ocsp": "pki-root-ocsp"} {
		cipher, err := store.Seal(label, files[name+"-key.pem"])
		if err != nil {
			return err
		}
		if err = exclusiveFile(filepath.Join(stage, name+".age"), cipher); err != nil {
			return err
		}
	}
	for _, name := range []string{"issuer.pem", "root.pem", "root-ocsp.pem", "root.crl.der"} {
		if err = exclusiveFile(filepath.Join(stage, name), files[name]); err != nil {
			return err
		}
	}
	if err = exclusiveFile(filepath.Join(stage, "recipient.txt"), []byte(store.Recipient()+"\n")); err != nil {
		return err
	}
	if err = syncDir(stage); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Recheck absence before rename; operator must serialize ceremonies to this
	// new output path. No service automatically changes its active configured epoch.
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		return ErrIssuer
	}
	if err = os.Rename(stage, output); err != nil {
		return ErrIssuer
	}
	return syncDir(filepath.Dir(output))
}
