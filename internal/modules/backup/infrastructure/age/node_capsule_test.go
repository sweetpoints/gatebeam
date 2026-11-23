package age

import (
	"context"
	"encoding/json"
	agefmt "filippo.io/age"
	"os"
	"path/filepath"
	"testing"
)

func TestCapsuleSetCannotMixNodeIdentities(t *testing.T) {
	dir := t.TempDir()
	offline, _ := agefmt.GenerateX25519Identity()
	online, _ := agefmt.GenerateX25519Identity()
	key := filepath.Join(t.TempDir(), "online")
	os.WriteFile(key, []byte(online.String()), 0600)
	a, b := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for _, role := range Roles {
		os.Mkdir(filepath.Join(dir, role), 0700)
		files := map[string]string{}
		for _, name := range RequiredFiles(role) {
			files[name] = key
		}
		node := a
		if role == "ca" {
			node = b
		}
		if e := ExportNodeCapsule(context.Background(), dir, role, "epoch", offline.Recipient().String(), node, 1, files); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := ReadCapsules(dir, "epoch", offline.Recipient().String()); e == nil {
		t.Fatal("A and B owner capsules mixed into one node backup")
	}
	// A forged public ref cannot relabel the encrypted owner binding.
	path := filepath.Join(dir, "ca", "current.json")
	body, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var ref capsuleRef
	if e = json.Unmarshal(body, &ref); e != nil {
		t.Fatal(e)
	}
	ref.NodeID = a
	body, _ = json.Marshal(ref)
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	collected, e := ReadCapsules(dir, "epoch", offline.Recipient().String())
	if e != nil {
		t.Fatal(e)
	}
	offlineFile := filepath.Join(t.TempDir(), "recovery.key")
	if e = os.WriteFile(offlineFile, []byte(offline.String()), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenCapsules(collected, "epoch", offlineFile); e == nil {
		t.Fatal("ciphertext owner binding bypassed by edited public ref")
	}
	ref.NodeID = b
	body, _ = json.Marshal(ref)
	if e = os.WriteFile(path, body, 0600); e != nil {
		t.Fatal(e)
	}
	// The original holder cannot relabel B's capsule tree as A, even with a new
	// backup key epoch. Replacement identities get fresh role-owned directories.
	caFiles := map[string]string{}
	for _, name := range RequiredFiles("ca") {
		caFiles[name] = key
	}
	if e := ExportNodeCapsule(context.Background(), dir, "ca", "next", offline.Recipient().String(), a, 1, caFiles); e == nil {
		t.Fatal("foreign node capsule directory adopted")
	}
}

func TestNodeCapsulesRoundTripAllOwners(t *testing.T) {
	dir := t.TempDir()
	offline, e := agefmt.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	online, e := agefmt.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(t.TempDir(), "owner")
	if e = os.WriteFile(key, []byte(online.String()), 0600); e != nil {
		t.Fatal(e)
	}
	for _, role := range Roles {
		if e = os.Mkdir(filepath.Join(dir, role), 0700); e != nil {
			t.Fatal(e)
		}
		files := map[string]string{}
		for _, name := range RequiredFiles(role) {
			files[name] = key
		}
		if e = ExportNodeCapsule(t.Context(), dir, role, "epoch", offline.Recipient().String(), "11111111-1111-4111-8111-111111111111", 2, files); e != nil {
			t.Fatal(e)
		}
	}
	collected, e := ReadCapsules(dir, "epoch", offline.Recipient().String())
	if e != nil {
		t.Fatal(e)
	}
	identity := filepath.Join(t.TempDir(), "offline")
	if e = os.WriteFile(identity, []byte(offline.String()), 0600); e != nil {
		t.Fatal(e)
	}
	opened, e := OpenCapsules(collected, "epoch", identity)
	if e != nil {
		t.Fatal(e)
	}
	want := 0
	for _, role := range Roles {
		want += len(RequiredFiles(role))
	}
	if len(opened) != want {
		t.Fatal("not all role capsules restored")
	}
}

func TestReviewManagementDrainStateDoesNotInvalidateCapsule(t *testing.T) {
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "edge"), 0700); e != nil {
		t.Fatal(e)
	}
	offline, _ := agefmt.GenerateX25519Identity()
	files := map[string]string{}
	for _, name := range append(RequiredFiles("edge"), "management-upstreams.json") {
		p := filepath.Join(t.TempDir(), name)
		if e := os.WriteFile(p, []byte("initial"), 0600); e != nil {
			t.Fatal(e)
		}
		files[name] = p
	}
	export := func() error {
		return ExportNodeCapsule(context.Background(), dir, "edge", "epoch", offline.Recipient().String(), "11111111-1111-4111-8111-111111111111", 1, files)
	}
	if e := export(); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(files["management-upstreams.json"], []byte("changed drain state"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := export(); e != nil {
		t.Fatalf("ordinary management drain update now prevents edge control startup: %v", e)
	}
}
