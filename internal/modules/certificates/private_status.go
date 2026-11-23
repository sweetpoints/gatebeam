package certificates

import (
	"encoding/json"
	"gatebeam/internal/modules/certificates/infrastructure/status"
	"io"
	"os"
)

func NewPrivateCRLSource(path string, trust []byte) (*status.PrivateCRLs, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	var profiles []status.Profile
	if d.Decode(&profiles) != nil || d.Decode(new(any)) != io.EOF {
		return nil, status.ErrStatus
	}
	return status.NewPrivateCRLs(profiles, trust)
}
