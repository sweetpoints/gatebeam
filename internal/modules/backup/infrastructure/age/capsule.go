package age

import (
	"bytes"
	"context"
	"encoding/json"
	agefmt "filippo.io/age"
	"gatebeam/internal/modules/backup/domain"
	"github.com/google/uuid"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

var Roles = []string{"api", "edge", "ca", "worker"}

func AllowedFiles(role string) []string {
	switch role {
	case "api":
		return []string{"identity.agekey", "api-tls.pem", "api-tls.key", "api-trust.pem", "api-client.crl", "acme-eab.json", "renewed-tls.pem"}
	case "ca":
		return []string{"identity.agekey", "issuer.age", "issuer.pem", "root.pem", "root.crl.der", "root-ocsp.pem", "root-ocsp.age", "tls.pem", "tls.key", "acme-eab.json", "renewed-tls.pem"}
	case "edge":
		return []string{"materials.agekey", "management.pem", "management.key", "management-trust.pem", "status-profiles.json", "api-client.pem", "api-client.key", "api-trust.pem", "management-upstreams.json", "acme-eab.json", "renewed-tls.pem"}
	case "worker":
		return []string{"provider.agekey", "notification.agekey", "acme-transport.pem"}
	}
	return nil
}

type Capsule struct {
	Role, Epoch string
	NodeID      string
	NodeEpoch   uint64
	Files       map[string][]byte
	History     []string
}
type capsuleRef struct {
	Epoch, Recipient, Fingerprint, Digest string
	KeyFingerprint                        string
	NodeID                                string
	NodeEpoch                             uint64
	History                               []string
}

const MaxHistory = 8

// ExportCapsule runs under the owning role, with fixed symbolic paths supplied
// by composition. Same-epoch key changes fail instead of silently losing keys.
func RequiredFiles(role string) []string {
	switch role {
	case "api":
		return []string{"identity.agekey"}
	case "ca":
		return []string{"identity.agekey", "issuer.age", "issuer.pem", "root.pem", "root.crl.der", "root-ocsp.pem", "root-ocsp.age", "tls.pem", "tls.key"}
	case "edge":
		return []string{"management.pem", "management.key", "management-trust.pem"}
	case "worker":
		return nil
	}
	return nil
}
func onlineKey(label string, b []byte, recipient string) bool {
	if !strings.HasSuffix(label, ".agekey") {
		return true
	}
	ids, e := agefmt.ParseIdentities(bytes.NewReader(b))
	if e != nil || len(ids) != 1 {
		return false
	}
	key, ok := ids[0].(*agefmt.X25519Identity)
	return ok && key.Recipient().String() != recipient
}
func ExportCapsule(ctx context.Context, dir, role, epoch, recipient string, paths map[string]string) error {
	return exportCapsule(ctx, dir, role, epoch, recipient, "", 0, paths)
}
func validCapsuleOwner(node string, epoch uint64) bool {
	if node == "" {
		return epoch == 0
	}
	id, e := uuid.Parse(node)
	return e == nil && id != uuid.Nil && id.String() == node && epoch > 0 && epoch <= math.MaxInt64
}
func ExportNodeCapsule(ctx context.Context, dir, role, epoch, recipient, node string, nodeEpoch uint64, paths map[string]string) error {
	if node == "" || !validCapsuleOwner(node, nodeEpoch) {
		return domain.ErrInvalid
	}
	return exportCapsule(ctx, dir, role, epoch, recipient, node, nodeEpoch, paths)
}
func exportCapsule(ctx context.Context, dir, role, epoch, recipient, node string, nodeEpoch uint64, paths map[string]string) error {
	if !slices.Contains(Roles, role) || !domain.ValidEpoch(epoch) {
		return domain.ErrInvalid
	}
	for _, required := range RequiredFiles(role) {
		if paths[required] == "" {
			return domain.ErrInvalid
		}
	}
	root, e := os.OpenRoot(filepath.Join(dir, role))
	if e != nil {
		return e
	}
	defer root.Close()
	var previous capsuleRef
	_, e = root.Lstat("current.json")
	if e == nil {
		b, err := ReadRegular(filepath.Join(dir, role, "current.json"), 4096)
		if err != nil || json.Unmarshal(b, &previous) != nil {
			return domain.ErrInvalid
		}
		if _, err = readRole(dir, role, previous); err != nil {
			return err
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if previous.Digest != "" && (previous.Recipient != recipient || previous.NodeID != "" && (previous.NodeID != node || previous.NodeEpoch > nodeEpoch)) {
		return domain.ErrInvalid
	}
	history := append([]string(nil), previous.History...)
	if previous.Digest != "" && previous.Epoch != epoch {
		history = append(history, previous.Digest)
	}
	sort.Strings(history)
	if len(history) > MaxHistory {
		return domain.ErrInvalid
	}
	c := Capsule{Role: role, Epoch: epoch, NodeID: node, NodeEpoch: nodeEpoch, Files: map[string][]byte{}, History: history}
	for label, path := range paths {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !slices.Contains(AllowedFiles(role), label) {
			return domain.ErrInvalid
		}
		b, err := ReadRegular(path, 1<<20)
		if err != nil || len(b) == 0 || !onlineKey(label, b, recipient) {
			return domain.ErrInvalid
		}
		c.Files[label] = b
	}
	// The recovery-key epoch guards historical decryption identities. Mutable
	// transport certificates and maintenance state have their own sealed snapshot.
	identityFiles := map[string][]byte{}
	for label, data := range c.Files {
		if strings.HasSuffix(label, ".agekey") || strings.HasSuffix(label, ".age") {
			identityFiles[label] = data
		}
	}
	identityBody, _ := json.Marshal(identityFiles)
	keyFingerprint := Digest(identityBody)
	body, _ := json.Marshal(c)
	fingerprint := Digest(body)
	if previous.Digest != "" && previous.Epoch == epoch {
		if previous.Recipient != recipient || previous.Fingerprint != fingerprint && (previous.KeyFingerprint == "" || previous.KeyFingerprint != keyFingerprint) {
			return domain.ErrInvalid
		}
		if previous.Fingerprint == fingerprint {
			return nil
		}
	}
	var sealed bytes.Buffer
	if e = Encrypt(&sealed, recipient, body); e != nil {
		return e
	}
	digest := Digest(sealed.Bytes())
	if e = exclusive(root, digest+".age", sealed.Bytes()); e != nil {
		return e
	}
	ref, _ := json.Marshal(capsuleRef{Epoch: epoch, Recipient: recipient, Fingerprint: fingerprint, KeyFingerprint: keyFingerprint, Digest: digest, History: history, NodeID: node, NodeEpoch: nodeEpoch})
	tmp := digest + ".current"
	if e = exclusive(root, tmp, ref); e != nil {
		return e
	}
	return root.Rename(tmp, "current.json")
}
func readRole(dir, role string, ref capsuleRef) (map[string][]byte, error) {
	if !domain.ValidEpoch(ref.Epoch) || !domain.ValidDigest(ref.Digest) || len(ref.History) > MaxHistory {
		return nil, domain.ErrInvalid
	}
	out := map[string][]byte{}
	seen := map[string]bool{}
	ids := append([]string{ref.Digest}, ref.History...)
	for i, id := range ids {
		if !domain.ValidDigest(id) || seen[id] {
			return nil, domain.ErrInvalid
		}
		seen[id] = true
		body, e := ReadRegular(filepath.Join(dir, role, id+".age"), domain.MaxFile)
		if e != nil || Digest(body) != id {
			return nil, domain.ErrInvalid
		}
		name := "capsules/" + role + ".age"
		if i > 0 {
			name = "capsules/" + role + "-" + id + ".age"
		}
		out[name] = body
	}
	return out, nil
}
func ReadCapsules(dir, epoch, recipient string) (map[string][]byte, error) {
	if !domain.ValidEpoch(epoch) {
		return nil, domain.ErrInvalid
	}
	out := map[string][]byte{}
	var ownerNode string
	var ownerEpoch uint64
	var ownerSet bool
	for _, role := range Roles {
		b, e := ReadRegular(filepath.Join(dir, role, "current.json"), 4096)
		if e != nil {
			return nil, e
		}
		var ref capsuleRef
		if json.Unmarshal(b, &ref) != nil || ref.Epoch != epoch || ref.Recipient != recipient || !validCapsuleOwner(ref.NodeID, ref.NodeEpoch) {
			return nil, domain.ErrInvalid
		}
		if ownerSet && (ownerNode != ref.NodeID || ownerEpoch != ref.NodeEpoch) {
			return nil, domain.ErrInvalid
		}
		ownerNode, ownerEpoch, ownerSet = ref.NodeID, ref.NodeEpoch, true
		files, e := readRole(dir, role, ref)
		if e != nil {
			return nil, e
		}
		for n, b := range files {
			out[n] = b
		}
	}
	return out, nil
}
func OpenCapsules(files map[string][]byte, epoch, identity string) (map[string][]byte, error) {
	raw, e := ReadRegular(identity, 4096)
	if e != nil {
		return nil, e
	}
	ids, e := agefmt.ParseIdentities(bytes.NewReader(raw))
	if e != nil || len(ids) != 1 {
		return nil, domain.ErrInvalid
	}
	key, ok := ids[0].(*agefmt.X25519Identity)
	if !ok {
		return nil, domain.ErrInvalid
	}
	recipient := key.Recipient().String()
	out := map[string][]byte{}
	var ownerNode string
	var ownerEpoch uint64
	var ownerSet bool
	for _, role := range Roles {
		current := files["capsules/"+role+".age"]
		body, e := Decrypt(current, identity)
		if e != nil {
			return nil, e
		}
		var head Capsule
		if json.Unmarshal(body, &head) != nil || head.Epoch != epoch || len(head.History) > MaxHistory {
			return nil, domain.ErrInvalid
		}
		if !validCapsuleOwner(head.NodeID, head.NodeEpoch) || ownerSet && (ownerNode != head.NodeID || ownerEpoch != head.NodeEpoch) {
			return nil, domain.ErrInvalid
		}
		ownerNode, ownerEpoch, ownerSet = head.NodeID, head.NodeEpoch, true
		seen := map[string]bool{}
		for _, id := range append([]string{Digest(current)}, head.History...) {
			if !domain.ValidDigest(id) || seen[id] {
				return nil, domain.ErrInvalid
			}
			seen[id] = true
		}
		count := 0
		for n := range files {
			if strings.HasPrefix(n, "capsules/"+role+"-") {
				count++
			}
		}
		if count != len(head.History) {
			return nil, domain.ErrInvalid
		}
		for i, id := range append([]string{Digest(current)}, head.History...) {
			cipher := current
			if i > 0 {
				cipher = files["capsules/"+role+"-"+id+".age"]
			}
			if Digest(cipher) != id {
				return nil, domain.ErrInvalid
			}
			body, e := Decrypt(cipher, identity)
			if e != nil {
				return nil, e
			}
			var c Capsule
			if json.Unmarshal(body, &c) != nil || c.Role != role || !validCapsuleOwner(c.NodeID, c.NodeEpoch) || c.NodeID != "" && (c.NodeID != head.NodeID || c.NodeEpoch > head.NodeEpoch) || !domain.ValidEpoch(c.Epoch) || len(c.Files) > len(AllowedFiles(role)) || len(c.History) > MaxHistory {
				return nil, domain.ErrInvalid
			}
			for _, h := range c.History {
				if !seen[h] {
					return nil, domain.ErrInvalid
				}
			}
			for _, required := range RequiredFiles(role) {
				if len(c.Files[required]) == 0 {
					return nil, domain.ErrInvalid
				}
			}
			for n, b := range c.Files {
				if !slices.Contains(AllowedFiles(role), n) || len(b) == 0 || len(b) > 1<<20 || !onlineKey(n, b, recipient) {
					return nil, domain.ErrInvalid
				}
				label := role + "/" + n
				if i > 0 {
					label = role + "/history/" + id + "/" + n
				}
				out[label] = b
			}
		}
	}
	return out, nil
}
