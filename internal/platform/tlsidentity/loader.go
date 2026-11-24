// Package tlsidentity reloads role-owned standard X.509 materials. It does not
// issue certificates, trust certificate-supplied URLs, or expose a network API.
package tlsidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("private TLS identity or status unavailable")

type Config struct {
	RenewedCertificateFile                                                      string
	FetchCRL                                                                    func(context.Context) ([]byte, error)
	CertificateFile, KeyFile, TrustFile, CRLFile, StateFile, NodeID, ServerName string
	ClientNames                                                                 []string
}
type statusFloor struct {
	NodeID  string
	At      time.Time
	Numbers map[string]string
	Revoked map[string]bool
}
type Loader struct {
	mu         sync.Mutex
	cfg        Config
	pair       *tls.Certificate
	pool       *x509.CertPool
	issuers    []*x509.Certificate
	crls       map[string]*x509.RevocationList
	floor      statusFloor
	fetchedCRL []byte
	nextFetch  time.Time
}

func read(path string) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() || s.Size() > 1<<20 {
		return nil, ErrUnavailable
	}
	return os.ReadFile(path)
}
func fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}
func New(c Config) (*Loader, error) {
	if c.ServerName == "" {
		if raw, e := read(c.CertificateFile); e == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if leaf, e := x509.ParseCertificate(block.Bytes); e == nil && len(leaf.DNSNames) > 0 {
					c.ServerName = leaf.DNSNames[0]
				}
			}
		}
	}
	l := &Loader{cfg: c, floor: statusFloor{NodeID: c.NodeID, Numbers: map[string]string{}, Revoked: map[string]bool{}}}
	if len(c.ClientNames) > 0 {
		if c.CRLFile == "" || c.StateFile == "" || c.NodeID == "" {
			return nil, ErrUnavailable
		}
		if raw, e := read(c.StateFile); e == nil {
			minimum, e := read(c.StateFile + ".minimum")
			h := sha256.Sum256(raw)
			if e != nil || string(minimum) != hex.EncodeToString(h[:]) {
				return nil, ErrUnavailable
			}
			if json.Unmarshal(raw, &l.floor) != nil || l.floor.NodeID != c.NodeID || l.floor.Numbers == nil || l.floor.Revoked == nil {
				return nil, ErrUnavailable
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			if _, minimumErr := os.Lstat(c.StateFile + ".minimum"); minimumErr == nil {
				return nil, ErrUnavailable
			}
			if _, e = os.Lstat(c.StateFile); !os.IsNotExist(e) {
				return nil, ErrUnavailable
			}
		}
	}
	if _, e := l.Config(); e != nil {
		return nil, e
	}
	return l, nil
}
func (l *Loader) save(now time.Time) error {
	if len(l.floor.Revoked) > 65536 || len(l.floor.Numbers) > 64 {
		return ErrUnavailable
	}
	l.floor.At = now
	raw, e := json.Marshal(l.floor)
	if e != nil {
		return e
	}
	dir := filepath.Dir(l.cfg.StateFile)
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return ErrUnavailable
	}
	write := func(path string, data []byte) error {
		f, e := os.CreateTemp(dir, ".tls-floor-")
		if e != nil {
			return e
		}
		name := f.Name()
		defer os.Remove(name)
		if e = f.Chmod(0600); e == nil {
			_, e = f.Write(data)
		}
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
		return os.Rename(name, path)
	}
	h := sha256.Sum256(raw)
	if e = write(l.cfg.StateFile+".minimum", []byte(hex.EncodeToString(h[:]))); e != nil {
		return e
	}
	if e = write(l.cfg.StateFile, raw); e != nil {
		return e
	}

	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (l *Loader) load(now time.Time) error {
	previous := l.pair
	// A partial certificate/key update cannot displace a valid active pair.
	certificatePath := l.cfg.CertificateFile
	if l.cfg.RenewedCertificateFile != "" {
		if raw, e := read(l.cfg.RenewedCertificateFile); e == nil {
			if key, e := read(l.cfg.KeyFile); e == nil {
				if pair, e := tls.X509KeyPair(raw, key); e == nil && len(pair.Certificate) > 0 {
					if leaf, e := x509.ParseCertificate(pair.Certificate[0]); e == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) {
						certificatePath = l.cfg.RenewedCertificateFile
					}
				}
				clear(key)
			}
		}
	}
	if cert, e := read(certificatePath); e == nil {
		if key, e := read(l.cfg.KeyFile); e == nil {
			p, e := tls.X509KeyPair(cert, key)
			clear(key)
			if e == nil && len(p.Certificate) > 0 {
				leaf, e := x509.ParseCertificate(p.Certificate[0])
				if e == nil && !leaf.IsCA && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter) {
					if l.cfg.ServerName == "" && len(leaf.DNSNames) > 0 {
						l.cfg.ServerName = leaf.DNSNames[0]
					}
					valid := false
					for _, usage := range leaf.ExtKeyUsage {
						valid = valid || usage == x509.ExtKeyUsageServerAuth
					}
					if valid && leaf.VerifyHostname(l.cfg.ServerName) == nil {
						p.Leaf = leaf
						l.pair = &p
					}
				}
			}
		}
	}
	if l.pair == nil || now.Before(l.pair.Leaf.NotBefore) || !now.Before(l.pair.Leaf.NotAfter) {
		return ErrUnavailable
	}
	if raw, e := read(l.cfg.TrustFile); e == nil {
		pool := x509.NewCertPool()
		var issuers []*x509.Certificate
		valid := true
		for len(bytes.TrimSpace(raw)) > 0 {
			block, rest := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" {
				valid = false
				break
			}
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil || !cert.IsCA {
				valid = false
				break
			}
			issuers = append(issuers, cert)
			if cert.CheckSignatureFrom(cert) == nil {
				pool.AddCert(cert)
			}
			raw = rest
		}
		if valid && len(issuers) > 0 {
			l.pool = pool
			l.issuers = issuers
		}
	}
	if l.cfg.TrustFile != "" && l.pool == nil {
		return ErrUnavailable
	}
	if l.cfg.TrustFile != "" {
		if l.pool == nil {
			return ErrUnavailable
		}
		intermediates := x509.NewCertPool()
		for _, issuer := range l.issuers {
			if issuer.CheckSignatureFrom(issuer) != nil {
				intermediates.AddCert(issuer)
			}
		}
		for _, der := range l.pair.Certificate[1:] {
			cert, e := x509.ParseCertificate(der)
			if e != nil {
				return ErrUnavailable
			}
			intermediates.AddCert(cert)
		}
		if _, e := l.pair.Leaf.Verify(x509.VerifyOptions{Roots: l.pool, Intermediates: intermediates, CurrentTime: now, DNSName: l.cfg.ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
			if previous == nil {
				return ErrUnavailable
			}
			oldIntermediates := x509.NewCertPool()
			for _, issuer := range l.issuers {
				if issuer.CheckSignatureFrom(issuer) != nil {
					oldIntermediates.AddCert(issuer)
				}
			}
			for _, raw := range previous.Certificate[1:] {
				cert, e := x509.ParseCertificate(raw)
				if e != nil {
					return ErrUnavailable
				}
				oldIntermediates.AddCert(cert)
			}
			if _, e = previous.Leaf.Verify(x509.VerifyOptions{Roots: l.pool, Intermediates: oldIntermediates, CurrentTime: now, DNSName: l.cfg.ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
				return ErrUnavailable
			}
			l.pair = previous
		}
	}
	if len(l.cfg.ClientNames) == 0 {
		return nil
	}
	raw, e := read(l.cfg.CRLFile)
	if l.cfg.FetchCRL != nil {
		if !now.Before(l.nextFetch) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			fresh, fetchErr := l.cfg.FetchCRL(ctx)
			cancel()
			// The authority may sign the CRL while this request is in flight.
			receivedAt := time.Now().UTC()
			if receivedAt.Before(now) {
				return ErrUnavailable
			}
			now = receivedAt
			l.nextFetch = now.Add(30 * time.Second)
			if fetchErr == nil {
				l.fetchedCRL = fresh
			}
		}
		if len(l.fetchedCRL) > 0 {
			raw = l.fetchedCRL
			e = nil
		}
	}
	if e != nil {
		return ErrUnavailable
	}
	lists := map[string]*x509.RevocationList{}
	if len(raw) > 0 && raw[0] != '-' {
		raw = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})
	}
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "X509 CRL" {
			return ErrUnavailable
		}
		r, e := x509.ParseRevocationList(block.Bytes)
		if e != nil || r.Number == nil || r.Number.Sign() < 0 || r.ThisUpdate.After(now) || !now.Before(r.NextUpdate) || !r.NextUpdate.After(r.ThisUpdate) {
			return ErrUnavailable
		}
		for _, extension := range r.Extensions {
			if extension.Critical {
				return ErrUnavailable
			}
		}
		for _, entry := range r.RevokedCertificateEntries {
			for _, extension := range entry.Extensions {
				if extension.Critical {
					return ErrUnavailable
				}
			}
			if entry.ReasonCode == 8 {
				return ErrUnavailable
			}
		}
		matched := false
		for _, issuer := range l.issuers {
			if !bytes.Equal(r.RawIssuer, issuer.RawSubject) || r.CheckSignatureFrom(issuer) != nil {
				continue
			}
			id := fingerprint(issuer)
			if old := l.floor.Numbers[id]; old != "" {
				n, ok := new(big.Int).SetString(old, 16)
				if !ok || r.Number.Cmp(n) < 0 {
					return ErrUnavailable
				}
			}
			l.floor.Numbers[id] = r.Number.Text(16)
			for _, entry := range r.RevokedCertificateEntries {
				if entry.RevocationTime.After(now) {
					return ErrUnavailable
				}
				l.floor.Revoked[id+"/"+entry.SerialNumber.Text(16)] = true
			}
			lists[id] = r
			matched = true
			break
		}
		if !matched {
			return ErrUnavailable
		}
		raw = rest
	}
	if len(lists) == 0 {
		return ErrUnavailable
	}
	l.crls = lists
	return l.save(now)
}
func (l *Loader) Config() (*tls.Config, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	if now.Before(l.floor.At) || l.load(now) != nil {
		return nil, ErrUnavailable
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*l.pair}, SessionTicketsDisabled: true}
	if len(l.cfg.ClientNames) > 0 {
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.ClientCAs = l.pool
		c.VerifyConnection = l.verify
	}
	return c, nil
}
func (l *Loader) verify(connection tls.ConnectionState) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	if now.Before(l.floor.At) || len(connection.PeerCertificates) == 0 || len(connection.VerifiedChains) == 0 {
		return ErrUnavailable
	}
	authorized := false
	for _, name := range l.cfg.ClientNames {
		authorized = authorized || connection.PeerCertificates[0].VerifyHostname(name) == nil
	}
	if !authorized {
		return ErrUnavailable
	}
	for _, chain := range connection.VerifiedChains {
		good := len(chain) > 1
		for i := 0; i+1 < len(chain); i++ {
			id := fingerprint(chain[i+1])
			r := l.crls[id]
			if r == nil || r.ThisUpdate.After(now) || !now.Before(r.NextUpdate) || l.floor.Revoked[id+"/"+chain[i].SerialNumber.Text(16)] {
				good = false
				break
			}
		}
		if good {
			return nil
		}
	}
	return ErrUnavailable
}
func (l *Loader) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return l.Config() }}
}
func (l *Loader) Ready() error { _, e := l.Config(); return e }
