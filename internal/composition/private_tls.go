package composition

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/modules/certificates"

	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"time"
)

func privateTLSOutput(c bootstrap.Config) string {
	if c.PrivateTLSRenewal == nil {
		return ""
	}
	return filepath.Join("/var/lib/gatebeam/capsules", c.Mode, "renewed-tls.pem")
}
func privateTLSPaths(c bootstrap.Config) (cert, key, purpose string) {
	switch c.Mode {
	case "api":
		return c.APITLSCertificateFile, c.APITLSKeyFile, "serverAuth"
	case "ca":
		return c.CATLSCertificateFile, c.CATLSKeyFile, "serverAuth"
	case "edge":
		return c.ManagementAPIClientCertificateFile, c.ManagementAPIClientKeyFile, "clientAuth"
	}
	return
}
func roleRenewalDetail(ctx context.Context, value string) {
	if state := lifecycle.FromContext(ctx); state != nil {
		state.SetDetail("tls_renewal", value)
		if value == "ready" {
			state.SetDetail("tls_renewal_stage", "")
		}
	}
}
func startPrivateTLS(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) func() {
	if c.PrivateTLSRenewal == nil {
		return func() {}
	}
	child, cancel := context.WithCancel(ctx)
	go func() {
		delay := c.PrivateTLSRenewal.CheckSeconds
		if delay == 0 {
			delay = 60
		}
		ticker := time.NewTicker(time.Duration(delay) * time.Second)
		defer ticker.Stop()
		var lastFailure time.Time
		for {
			e := renewPrivateTLS(child, c, p)
			if e != nil && child.Err() == nil {
				roleRenewalDetail(child, "degraded")
				var failure certificates.PrivateTLSFailure
				if errors.As(e, &failure) {
					if state := lifecycle.FromContext(child); state != nil {
						state.SetDetail("tls_renewal_stage", failure.Stage)
					}
				}
				if time.Since(lastFailure) >= time.Minute {
					fmt.Fprintln(os.Stderr, "private role TLS renewal unavailable; valid active material retained")
					lastFailure = time.Now()
				}
			} else if e == nil {
				roleRenewalDetail(child, "ready")
			}
			select {
			case <-child.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return cancel
}
func renewPrivateTLS(ctx context.Context, c bootstrap.Config, p *pgxpool.Pool) (err error) {
	stage := "bootstrap"
	defer func() {
		if err != nil {
			var failure certificates.PrivateTLSFailure
			if !errors.As(err, &failure) {
				err = certificates.PrivateTLSFailure{Stage: stage, Cause: err}
			}
		}
	}()

	policy := c.PrivateTLSRenewal
	if policy == nil {
		return nil
	}
	certFile, keyFile, purpose := privateTLSPaths(c)
	if certFile == "" || keyFile == "" {
		return errors.New("private role TLS ownership unavailable")
	}
	read := func(path string) ([]byte, error) {
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
			return nil, errors.New("private renewal input unavailable")
		}
		return os.ReadFile(path)
	}
	key, e := read(keyFile)
	if e != nil {
		return e
	}
	defer clear(key)
	bootstrapCert, e := read(certFile)
	if e != nil {
		return e
	}
	initial, e := tls.X509KeyPair(bootstrapCert, key)
	if e != nil || len(initial.Certificate) == 0 {
		return errors.New("private bootstrap pair invalid")
	}
	leaf, e := x509.ParseCertificate(initial.Certificate[0])
	if e != nil || len(leaf.DNSNames) == 0 {
		return errors.New("private bootstrap names unavailable")
	}
	output := privateTLSOutput(c)
	if raw, e := read(output); e == nil {
		if pair, e := tls.X509KeyPair(raw, key); e == nil && len(pair.Certificate) > 0 {
			if current, e := x509.ParseCertificate(pair.Certificate[0]); e == nil {
				before := time.Duration(policy.RenewBeforeSeconds) * time.Second
				if before == 0 {
					before = current.NotAfter.Sub(current.NotBefore) / 3
				}
				if time.Until(current.NotAfter) > before {
					return nil
				}
			}
		}
	}
	stage = "eab"
	raw, e := read(policy.EABFile)
	if e != nil {
		return e
	}
	defer clear(raw)
	var credentials struct {
		KeyID     string    `json:"kid"`
		HMAC      string    `json:"hmac"`
		Directory string    `json:"directory"`
		Expires   time.Time `json:"expires"`
	}
	if json.Unmarshal(raw, &credentials) != nil || credentials.KeyID == "" || credentials.HMAC == "" {
		return errors.New("standard EAB credentials unavailable")
	}
	directory := "server"
	if purpose == "clientAuth" {
		directory = "client"
	}
	if credentials.Directory != directory {
		return errors.New("standard EAB directory mismatch")
	}
	trust, e := read(policy.TrustFile)
	if e != nil {
		return e
	}
	request, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var challenge certificates.PrivateHTTPChallenges
	if c.Mode == "edge" {
		challenge, e = certificates.NewPrivateLocalHTTPChallenges(request, c.ACMEWebRoot)
		if e != nil {
			return e
		}
	} else {
		challenge = certificates.NewHTTPChallenges(p, certificatematerials.ReadOnlyChallengeNodes{Nodes: deployment.NewNodes()})
	}
	stage = "persist-directory"
	dir := filepath.Dir(output)
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("private renewal retained directory unavailable")
	}
	stage = "acme"
	certificate, e := certificates.ObtainPrivateTLS(request, certificates.PrivateTLSRequest{Origin: policy.Origin, Email: policy.Email, KeyID: credentials.KeyID, HMAC: credentials.HMAC, Purpose: purpose, Names: leaf.DNSNames, PrivateKey: key, TransportTrust: trust}, challenge)
	if e != nil {
		return e
	}
	stage = "persist-directory"

	stage = "persist-create"
	f, e := os.CreateTemp(dir, ".renewed-tls-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	stage = "persist-write"
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(certificate)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	stage = "persist-switch"
	if e = os.Rename(name, output); e != nil {
		return e
	}
	stage = "persist-sync"
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	e = errors.Join(d.Sync(), d.Close())
	if e != nil {
		return e
	}
	stage = "reload"
	if c.Mode == "edge" {
		sum := sha256.Sum256(certificate)
		return postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
			_, e := jobs.New(p).EnqueueTargetWithin(sc, "deployment.node.generation.v1", "private-tls/"+hex.EncodeToString(sum[:]), json.RawMessage(`{"kind":"management"}`), jobs.ClaimTarget{NodeID: c.NodeID, Epoch: c.NodeEpoch})
			return e
		})
	}
	return nil
}
