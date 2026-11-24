package age

import (
	"context"
	agefmt "filippo.io/age"
	"os"
	"path/filepath"
	"testing"
)

func TestCapsulesRequireAllRolesSameEpochAndKeyRotation(t *testing.T) {
	dir := t.TempDir()
	key, _ := agefmt.GenerateX25519Identity()
	file := filepath.Join(t.TempDir(), "key")
	online, _ := agefmt.GenerateX25519Identity()
	os.WriteFile(file, []byte(online.String()), 0600)
	if _, e := ReadCapsules(dir, "epoch", key.Recipient().String()); e == nil {
		t.Fatal("missing role capsules accepted")
	}
	for _, role := range Roles {
		os.Mkdir(filepath.Join(dir, role), 0700)
		paths := map[string]string{}
		for _, n := range AllowedFiles(role) {
			paths[n] = file
		}
		if e := ExportCapsule(context.Background(), dir, role, "epoch", key.Recipient().String(), paths); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := ReadCapsules(dir, "epoch", key.Recipient().String()); e != nil {
		t.Fatal(e)
	}
	replacement, _ := agefmt.GenerateX25519Identity()
	os.WriteFile(file, []byte(replacement.String()), 0600)
	if e := ExportCapsule(context.Background(), dir, "api", "epoch", key.Recipient().String(), map[string]string{AllowedFiles("api")[0]: file}); e == nil {
		t.Fatal("key rotation silently reused epoch")
	}
	if e := ExportCapsule(context.Background(), dir, "api", "new-epoch", key.Recipient().String(), map[string]string{AllowedFiles("api")[0]: file}); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadCapsules(dir, "epoch", key.Recipient().String()); e == nil {
		t.Fatal("mixed role epochs accepted")
	}
	if e := ExportCapsule(context.Background(), dir, "api", "next", key.Recipient().String(), map[string]string{"root-key.pem": file}); e == nil {
		t.Fatal("offline root accepted")
	}
}

func TestHistoricalCapsulesPreserveKeysAndMissingHistoryFails(t *testing.T) {
	dir := t.TempDir()
	recovery, _ := agefmt.GenerateX25519Identity()
	identity := filepath.Join(t.TempDir(), "recovery")
	os.WriteFile(identity, []byte(recovery.String()), 0600)
	old, _ := agefmt.GenerateX25519Identity()
	online := filepath.Join(t.TempDir(), "online")
	os.WriteFile(online, []byte(old.String()), 0600)
	for _, role := range Roles {
		os.Mkdir(filepath.Join(dir, role), 0700)
		paths := map[string]string{}
		for _, n := range AllowedFiles(role) {
			paths[n] = online
		}
		if e := ExportCapsule(context.Background(), dir, role, "first", recovery.Recipient().String(), paths); e != nil {
			t.Fatal(e)
		}
	}
	before, e := ReadCapsules(dir, "first", recovery.Recipient().String())
	if e != nil {
		t.Fatal(e)
	}
	oldDigest := Digest(before["capsules/api.age"])
	replacement, _ := agefmt.GenerateX25519Identity()
	os.WriteFile(online, []byte(replacement.String()), 0600)
	for _, role := range Roles {
		paths := map[string]string{}
		for _, n := range AllowedFiles(role) {
			paths[n] = online
		}
		if e := ExportCapsule(context.Background(), dir, role, "second", recovery.Recipient().String(), paths); e != nil {
			t.Fatal(e)
		}
	}
	after, e := ReadCapsules(dir, "second", recovery.Recipient().String())
	if e != nil {
		t.Fatal(e)
	}
	if len(after) != 8 {
		t.Fatalf("historical role capsules omitted: got %d want 8", len(after))
	}
	opened, e := OpenCapsules(after, "second", identity)
	if e != nil {
		t.Fatal(e)
	}
	if string(opened["api/history/"+oldDigest+"/identity.agekey"]) != old.String() {
		t.Fatal("old ciphertext decryption identity unavailable after rotation")
	}
	os.Remove(filepath.Join(dir, "api", oldDigest+".age"))
	if _, e = ReadCapsules(dir, "second", recovery.Recipient().String()); e == nil {
		t.Fatal("missing required historical capsule silently ignored")
	}
}

func TestExternalCABackupDoesNotRequireOrAcceptAuthorityCapsules(t *testing.T) {
	dir := t.TempDir()
	recovery, err := agefmt.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	online, err := agefmt.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity, source := filepath.Join(dir, "recovery"), filepath.Join(dir, "online")
	for path, key := range map[string]*agefmt.X25519Identity{identity: recovery, source: online} {
		if err := os.WriteFile(path, []byte(key.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range CapsuleRoles(true) {
		if err := os.Mkdir(filepath.Join(dir, role), 0700); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{}
		for _, name := range AllowedFiles(role) {
			files[name] = source
		}
		if err := ExportCapsule(t.Context(), dir, role, "epoch", recovery.Recipient().String(), files); err != nil {
			t.Fatal(err)
		}
	}
	capsules, err := ReadCapsulesForCA(dir, "epoch", recovery.Recipient().String(), true)
	if err != nil || len(capsules) != 3 {
		t.Fatalf("gateway capsules: count=%d err=%v", len(capsules), err)
	}
	if _, err := OpenCapsulesForCA(capsules, "epoch", identity, true); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCapsules(capsules, "epoch", identity); err == nil {
		t.Fatal("legacy archive accepted without its CA capsule")
	}
	capsules["capsules/ca.age"] = capsules["capsules/api.age"]
	if _, err := OpenCapsulesForCA(capsules, "epoch", identity, true); err == nil {
		t.Fatal("gateway archive accepted an authority capsule")
	}
}
