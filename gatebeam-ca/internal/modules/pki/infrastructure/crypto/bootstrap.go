package pkicrypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/platform/secrets"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Bootstrapper struct{}

func exclusiveFile(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrIssuer
	}
	defer f.Close()
	if _, e = f.Write(data); e != nil {
		return ErrIssuer
	}
	if e = f.Sync(); e != nil {
		return ErrIssuer
	}
	if e = f.Close(); e != nil {
		return ErrIssuer
	}
	return nil
}
func syncDir(path string) error {
	d, e := os.Open(path)
	if e != nil {
		return ErrIssuer
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return ErrIssuer
	}
	return nil
}
func newPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrIssuer
	}
	path = filepath.Clean(path)
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return "", ErrIssuer
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return "", ErrIssuer
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

// Generate is an offline ceremony. Its output directories must be new siblings
// (or in disjoint existing parents), never nested. Only online output is mounted
// into the CA. No key or CSR is written to stdout or returned in an error.
func (Bootstrapper) Generate(ctx context.Context, c application.BootstrapCommand) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if strings.TrimSpace(c.RootName) == "" || strings.TrimSpace(c.IntermediateName) == "" || len(c.RootName) > 64 || len(c.IntermediateName) > 64 {
		return ErrIssuer
	}
	rootDir, e := newPath(c.RootDirectory)
	if e != nil {
		return e
	}
	onlineDir, e := newPath(c.OnlineDirectory)
	if e != nil {
		return e
	}
	if rootDir == onlineDir || strings.HasPrefix(rootDir, onlineDir+string(os.PathSeparator)) || strings.HasPrefix(onlineDir, rootDir+string(os.PathSeparator)) {
		return ErrIssuer
	}
	rootKey, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		return ErrIssuer
	}
	onlineKey, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		return ErrIssuer
	}
	rootSerial, e := NewSerial()
	if e != nil {
		return e
	}
	onlineSerial, e := NewSerial()
	if e != nil {
		return e
	}
	now := time.Now().UTC().Truncate(time.Second)
	rt := &x509.Certificate{SerialNumber: rootSerial, Subject: pkix.Name{CommonName: c.RootName}, NotBefore: now, NotAfter: now.AddDate(10, 0, 0), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, rt, rt, &rootKey.PublicKey, rootKey)
	if e != nil {
		return ErrIssuer
	}
	root, e := x509.ParseCertificate(rootDER)
	if e != nil {
		return ErrIssuer
	}
	it := &x509.Certificate{SerialNumber: onlineSerial, Subject: pkix.Name{CommonName: c.IntermediateName}, NotBefore: now, NotAfter: now.AddDate(1, 0, 0), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if c.StatusOrigin != "" {
		u, e := url.Parse(c.StatusOrigin)
		if e != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return ErrIssuer
		}
		it.OCSPServer = []string{c.StatusOrigin + "/ocsp"}
		it.CRLDistributionPoints = []string{c.StatusOrigin + "/crl/root.der"}
	}
	interDER, e := x509.CreateCertificate(rand.Reader, it, root, &onlineKey.PublicKey, rootKey)
	if e != nil {
		return ErrIssuer
	}
	delegateKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return ErrIssuer
	}
	delegateSerial, e := NewSerial()
	if e != nil {
		return e
	}
	if delegateSerial.Cmp(rootSerial) == 0 || delegateSerial.Cmp(onlineSerial) == 0 || rootSerial.Cmp(onlineSerial) == 0 {
		return ErrIssuer
	}
	dt := &x509.Certificate{SerialNumber: delegateSerial, Subject: pkix.Name{CommonName: "Root OCSP delegate"}, NotBefore: now, NotAfter: it.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	delegateDER, e := x509.CreateCertificate(rand.Reader, dt, root, &delegateKey.PublicKey, rootKey)
	if e != nil {
		return ErrIssuer
	}
	delegatePKCS8, e := x509.MarshalPKCS8PrivateKey(delegateKey)
	if e != nil {
		return ErrIssuer
	}
	defer clear(delegatePKCS8)
	rootCRL, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(30 * 24 * time.Hour)}, root, rootKey)
	if e != nil {
		return ErrIssuer
	}
	rootPKCS8, e := x509.MarshalPKCS8PrivateKey(rootKey)
	if e != nil {
		return ErrIssuer
	}
	defer clear(rootPKCS8)
	onlinePKCS8, e := x509.MarshalPKCS8PrivateKey(onlineKey)
	if e != nil {
		return ErrIssuer
	}
	defer clear(onlinePKCS8)
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = os.Mkdir(rootDir, 0700); e != nil {
		return ErrIssuer
	}
	rootOwned := true
	onlineOwned := false
	complete := false
	defer func() {
		if !complete {
			if onlineOwned {
				_ = os.RemoveAll(onlineDir)
			}
			if rootOwned {
				_ = os.RemoveAll(rootDir)
			}
		}
	}()
	if e = os.Mkdir(onlineDir, 0700); e != nil {
		return ErrIssuer
	}
	onlineOwned = true
	identity := filepath.Join(onlineDir, "identity.agekey")
	if e = secrets.EnsureIdentity(identity); e != nil {
		return ErrIssuer
	}
	store, e := secrets.New(identity)
	if e != nil {
		return ErrIssuer
	}
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: onlinePKCS8})
	defer clear(plain)
	cipher, e := store.Seal("pki-online-issuer", plain)
	if e != nil {
		return ErrIssuer
	}
	delegatePlain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: delegatePKCS8})
	defer clear(delegatePlain)
	delegateCipher, e := store.Seal("pki-root-ocsp", delegatePlain)
	if e != nil {
		return ErrIssuer
	}
	files := []struct {
		path string
		data []byte
	}{
		{filepath.Join(rootDir, "root-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootPKCS8})},
		{filepath.Join(rootDir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})},
		{filepath.Join(onlineDir, "root.crl.der"), rootCRL},
		{filepath.Join(rootDir, "root.crl.der"), rootCRL},
		{filepath.Join(onlineDir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})},
		{filepath.Join(onlineDir, "issuer.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})},
		{filepath.Join(onlineDir, "issuer.age"), cipher},
		{filepath.Join(onlineDir, "root-ocsp.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: delegateDER})},
		{filepath.Join(onlineDir, "root-ocsp.age"), delegateCipher},
		{filepath.Join(onlineDir, "recipient.txt"), []byte(store.Recipient() + "\n")},
	}
	defer clear(files[0].data)
	for _, f := range files {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = exclusiveFile(f.path, f.data); e != nil {
			return e
		}
	}
	for _, dir := range []string{rootDir, onlineDir, filepath.Dir(rootDir), filepath.Dir(onlineDir)} {
		if e = syncDir(dir); e != nil {
			return e
		}
	}
	complete = true
	return nil
}
