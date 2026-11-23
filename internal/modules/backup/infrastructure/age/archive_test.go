package age

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	agefmt "filippo.io/age"
	"gatebeam/internal/modules/backup/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHostileArchivePathsAndSymlinksRejected(t *testing.T) {
	key, _ := agefmt.GenerateX25519Identity()
	dir := t.TempDir()
	identity := filepath.Join(dir, "offline")
	os.WriteFile(identity, []byte(key.String()), 0600)
	for _, tc := range []struct {
		name string
		kind byte
	}{{"../../escape", tar.TypeReg}, {"/etc/passwd", tar.TypeReg}, {"capsules/api.age", tar.TypeSymlink}, {"keys/root-key.pem", tar.TypeReg}, {"database/identity_accounts.sql", tar.TypeReg}} {
		t.Run(tc.name, func(t *testing.T) {
			var raw bytes.Buffer
			tw := tar.NewWriter(&raw)
			h := &tar.Header{Name: tc.name, Typeflag: tc.kind, Mode: 0600, Linkname: "/etc/passwd"}
			if e := tw.WriteHeader(h); e != nil {
				t.Fatal(e)
			}
			m := domain.Manifest{Version: 1, ID: strings.Repeat("a", 64), Schema: strings.Repeat("b", 64), Epoch: "epoch", Snapshot: "snapshot", Created: time.Now(), Files: []domain.File{{Name: tc.name, SHA256: Digest(nil)}}}
			b, _ := json.Marshal(m)
			tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: int64(len(b))})
			tw.Write(b)
			tw.Close()
			var sealed bytes.Buffer
			if e := Encrypt(&sealed, key.Recipient().String(), raw.Bytes()); e != nil {
				t.Fatal(e)
			}
			source := filepath.Join(t.TempDir(), "bad.age")
			os.WriteFile(source, sealed.Bytes(), 0600)
			if _, _, e := (Decoder{}).Decode(context.Background(), source, identity); e == nil {
				t.Fatal("hostile tar entry accepted")
			}
		})
	}
	source := filepath.Join(dir, "linked")
	os.Symlink(identity, source)
	if _, e := ReadRegular(source, 4096); e == nil {
		t.Fatal("symlink source accepted")
	}
}
