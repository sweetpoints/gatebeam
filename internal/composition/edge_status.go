package composition

import (
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/modules/certificates"
	"gatebeam/internal/modules/certificates/infrastructure/ocspcache"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/platform/bootstrap"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

// startEdgeStatus is the same in-process standard OCSP responder during
// controlled initialization and every subsequent local-only restart.
func startEdgeStatus(c bootstrap.Config, initial *edge.RuntimeState) (*certificatematerials.OfflineStatus, func(), error) {
	cache, e := certificates.NewOfflineStatusCache(filepath.Join(c.EdgeRoot, "ocsp-cache"))
	if e != nil {
		return nil, nil, e
	}
	offline := &certificatematerials.OfflineStatus{Service: cache, Configure: func(issuers [][]byte) error {
		return certificates.ConfigureOfflineStatusCache(cache, issuers, c.CertificateStatusProfilesFile)
	}}
	if initial != nil {
		if e = offline.Bind(initial); e != nil {
			return nil, nil, e
		}
	}
	listener, e := net.Listen("tcp", "127.0.0.1:9091")
	if e != nil {
		return nil, nil, e
	}
	server := &http.Server{Handler: ocspcache.Handler(cache), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	go func() { _ = server.Serve(listener) }()
	return offline, func() { _ = server.Close() }, nil
}
