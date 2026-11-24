package composition

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// withWeb serves only build output supplied by the trusted process assembly.
// API paths and unknown routes never fall back to the SPA shell.
func withWeb(api http.Handler, bundle fs.FS) http.Handler {
	assets := http.FileServer(http.FS(bundle))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shell := r.URL.Path == "/" || r.URL.Path == "/login" || r.URL.Path == "/enroll" || r.URL.Path == "/recover" || r.URL.Path == "/console/sites" || r.URL.Path == "/console/targets" || r.URL.Path == "/console/releases" || r.URL.Path == "/console/certificates" || r.URL.Path == "/console/credentials" || r.URL.Path == "/console/overview" || r.URL.Path == "/console/logs" || r.URL.Path == "/console/alerts" || r.URL.Path == "/console/backups" || r.URL.Path == "/console/accounts" || r.URL.Path == "/console/audit"
		asset := strings.HasPrefix(r.URL.Path, "/assets/")
		if !shell && !asset {
			api.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if shell {
			html, e := fs.ReadFile(bundle, "index.html")
			if e != nil {
				http.Error(w, "管理界面尚未构建", 503)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method == "GET" {
				_, _ = w.Write(html)
			}
			return
		}
		if path.Clean(r.URL.Path) != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		info, e := fs.Stat(bundle, strings.TrimPrefix(r.URL.Path, "/"))
		if e != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		assets.ServeHTTP(w, r)
	})
}
