// Package domain defines bounded backup and conservative recovery policy.
package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid backup or recovery input")

const MaxArchive = 128 << 20
const MaxFile = 32 << 20
const MaxRow = 8 << 20
const MaxRows = 100000

var hex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var epoch = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type Policy struct {
	Retain time.Duration
	MaxAge time.Duration
}
type Manifest struct {
	ExternalCA bool `json:",omitempty"`
	Version    int
	ID         string
	Created    time.Time
	Snapshot   string
	Epoch      string
	Schema     string
	Recipient  string
	Files      []File
}
type File struct {
	Name   string
	Bytes  int64
	SHA256 string
}

func ValidDigest(v string) bool { return hex.MatchString(v) }
func ValidEpoch(v string) bool  { return epoch.MatchString(v) }
func (p Policy) Validate() error {
	if p.Retain < 24*time.Hour || p.Retain > 365*24*time.Hour || p.MaxAge < time.Minute || p.MaxAge > 24*time.Hour || p.MaxAge >= p.Retain {
		return ErrInvalid
	}
	return nil
}
func (m Manifest) Validate() error {
	if m.Version != 1 || !ValidDigest(m.ID) || m.Created.IsZero() || len(m.Snapshot) == 0 || len(m.Snapshot) > 256 || len(m.Recipient) > 128 || !ValidEpoch(m.Epoch) || !ValidDigest(m.Schema) || len(m.Files) == 0 || len(m.Files) > 128 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	var size int64
	for _, f := range m.Files {
		if seen[f.Name] || !ValidName(f.Name) || f.Bytes < 0 || f.Bytes > MaxFile || !ValidDigest(f.SHA256) {
			return ErrInvalid
		}
		seen[f.Name] = true
		size += f.Bytes
	}
	if size > MaxArchive {
		return ErrInvalid
	}
	return nil
}

// Archive paths are symbolic data labels, never operating-system paths or SQL.
func ValidName(v string) bool {
	if strings.HasPrefix(v, "database/") && strings.HasSuffix(v, ".json") {
		return regexp.MustCompile(`^database/[a-z][a-z0-9_]{0,80}\.json$`).MatchString(v)
	}
	for _, role := range []string{"api", "ca", "edge", "worker"} {
		if v == "capsules/"+role+".age" || (strings.HasPrefix(v, "capsules/"+role+"-") && strings.HasSuffix(v, ".age") && ValidDigest(strings.TrimSuffix(strings.TrimPrefix(v, "capsules/"+role+"-"), ".age"))) {
			return true
		}
	}
	return false
}
