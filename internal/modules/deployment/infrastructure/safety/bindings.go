// Package safety binds confirmed security inputs independently of boot artifacts.
package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	edge "gatebeam/internal/modules/deployment/application/runtime"
)

func Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Bindings(r edge.RuntimeState) map[string]string {
	out := map[string]string{"cloudflare": Digest(r.Cloudflare), "management": Digest(r.Management)}
	for id, m := range r.Materials {
		out["material/"+id] = Digest(m)
	}
	return out
}
