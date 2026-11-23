//go:build integration

package pki_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
)

type nginxImageMetadata struct {
	ID           string `json:"Id"`
	RepoDigests  []string
	Architecture string
	Os           string
}

// The pinned reference identifies an OCI index. Id identifies the selected
// platform configuration, so it must be validated independently of that pin.
func validatePinnedNginxMetadata(raw, architecture string) error {
	var images []nginxImageMetadata
	if json.Unmarshal([]byte(raw), &images) != nil || len(images) != 1 {
		return errors.New("invalid image metadata")
	}
	image := images[0]
	if image.Os != "linux" || image.Architecture != architecture {
		return errors.New("unexpected image platform")
	}
	digest := strings.TrimPrefix(image.ID, "sha256:")
	if image.ID == digest || len(digest) != 64 {
		return errors.New("invalid image config digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return errors.New("invalid image config digest")
	}
	for _, reference := range image.RepoDigests {
		if reference == nginxImage || reference == "docker.io/library/"+nginxImage {
			return nil
		}
	}
	return errors.New("immutable image repository digest mismatch")
}

func requirePinnedNginx(t *testing.T) {
	t.Helper()
	if err := validatePinnedNginxMetadata(command(t, "image", "inspect", nginxImage), runtime.GOARCH); err != nil {
		t.Fatal("unexpected Nginx artifact", err)
	}
}

func TestPinnedNginxMetadataUsesRepositoryDigest(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			valid := nginxImageMetadata{ID: "sha256:" + strings.Repeat("a", 64), RepoDigests: []string{nginxImage}, Architecture: architecture, Os: "linux"}
			encode := func(images ...nginxImageMetadata) string {
				raw, err := json.Marshal(images)
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			}
			fullReference := valid
			fullReference.RepoDigests = []string{"docker.io/library/" + nginxImage}
			wrongReference := valid
			wrongReference.RepoDigests = []string{"nginx@sha256:" + strings.Repeat("f", 64)}
			noReference := valid
			noReference.RepoDigests = nil
			wrongPlatform := valid
			wrongPlatform.Architecture = "other"
			wrongOS := valid
			wrongOS.Os = "windows"
			invalidConfig := valid
			invalidConfig.ID = "sha256:" + strings.Repeat("z", 64)
			for _, tc := range []struct {
				name, raw string
				valid     bool
			}{
				{"selected_config_differs_from_index", encode(valid), true},
				{"fully_qualified_reference", encode(fullReference), true},
				{"wrong_repository_digest", encode(wrongReference), false},
				{"missing_repository_digest", encode(noReference), false},
				{"wrong_platform", encode(wrongPlatform), false},
				{"wrong_os", encode(wrongOS), false},
				{"invalid_config_digest", encode(invalidConfig), false},
				{"multiple_images", encode(valid, valid), false},
				{"empty_images", "[]", false},
				{"malformed_metadata", "not json", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					err := validatePinnedNginxMetadata(tc.raw, architecture)
					if (err == nil) != tc.valid {
						t.Fatal("incorrect immutable image identity result", err)
					}
				})
			}
		})
	}
}
