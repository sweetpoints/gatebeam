package domain

import (
	"regexp"
	"strings"
	"time"
)

const BootFormat = 1

var bootDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BootManifest binds local files to an authorized, actually applied generation.
// A prepared manifest alone is not proof of successful native activation.
type BootManifest struct {
	Format                          uint32
	Node                            NodeRef
	ArtifactID, Version, Generation string
	AuthorizationID                 string
	CreatedAt                       time.Time
	MaterialIDs                     []string
	FileDigests                     map[string]string
}

func (m BootManifest) Validate() error {
	if m.Format != BootFormat || !m.Node.Valid() || !bootDigest.MatchString(m.ArtifactID) || !bootToken(m.Version) || !bootToken(m.Generation) || !bootToken(m.AuthorizationID) || m.CreatedAt.IsZero() || len(m.MaterialIDs) > 4096 || len(m.FileDigests) > 10000 {
		return ErrInvalid
	}
	for _, id := range m.MaterialIDs {
		if !bootToken(id) {
			return ErrInvalid
		}
	}
	for name, digest := range m.FileDigests {
		if name == "" || len(name) > 1024 || !bootDigest.MatchString(digest) {
			return ErrInvalid
		}
	}
	return nil
}

func bootToken(v string) bool {
	return v != "" && len(v) <= 512 && !strings.ContainsAny(v, "\x00\r\n")
}

// SecurityFloor is separate from a configuration checkpoint, so selecting an
// earlier configuration cannot erase already known revocations or trusted time.
type SecurityFloor struct {
	Node               NodeRef
	Sequence           uint64
	RecordedAt         time.Time
	RevokedMaterialIDs []string
	AuthorizationID    string
	SecurityBindings   map[string]string
}

func (f SecurityFloor) Validate() error {
	if !f.Node.Valid() || f.RecordedAt.IsZero() || len(f.RevokedMaterialIDs) > 4096 {
		return ErrInvalid
	}
	if len(f.SecurityBindings) > 4098 || f.AuthorizationID != "" && !bootToken(f.AuthorizationID) {
		return ErrInvalid
	}
	for key, value := range f.SecurityBindings {
		if !bootToken(key) || !bootDigest.MatchString(value) {
			return ErrInvalid
		}
	}
	for _, id := range f.RevokedMaterialIDs {
		if !bootToken(id) {
			return ErrInvalid
		}
	}
	return nil
}
