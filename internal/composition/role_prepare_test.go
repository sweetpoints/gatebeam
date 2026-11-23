package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleIdentityPreparationNeverCopiesOrOverwritesKeys(t *testing.T) {
	root := t.TempDir()
	a := bootstrap.Config{Mode: "edge", RuntimeProtocol: 1, NodeID: "11111111-1111-4111-8111-111111111111", NodeEpoch: 1, CertificateIdentityFile: filepath.Join(root, "a.agekey")}
	b := a
	b.NodeID = "22222222-2222-4222-8222-222222222222"
	b.CertificateIdentityFile = filepath.Join(root, "b.agekey")
	pa, e := PrepareRoleIdentity(context.Background(), a)
	if e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(a.CertificateIdentityFile)
	if e != nil {
		t.Fatal(e)
	}
	pb, e := PrepareRoleIdentity(context.Background(), b)
	if e != nil || pa["leaf"] == pb["leaf"] {
		t.Fatal("independent nodes did not get independent age identities", e)
	}
	again, e := PrepareRoleIdentity(context.Background(), a)
	after, _ := os.ReadFile(a.CertificateIdentityFile)
	if e != nil || again["leaf"] != pa["leaf"] || !bytes.Equal(before, after) {
		t.Fatal("existing key replaced", e)
	}
}

func TestOperatorCanPrepareFirstIdentityBeforeDBAndSignerExist(t *testing.T) {
	for _, mode := range []string{"api", "ca"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			cfg := bootstrap.Config{Environment: "production", Mode: mode, RuntimeProtocol: 1, NodeID: "11111111-1111-4111-8111-111111111111", NodeEpoch: 1, DatabaseFile: filepath.Join(root, "missing-database")}
			key := filepath.Join(root, "first.agekey")
			if mode == "api" {
				cfg.IdentityFile = key
			} else {
				cfg.CAIdentityFile = key
				cfg.CASignerFile = filepath.Join(root, "missing-signer")
				cfg.CARootOCSPSignerFile = filepath.Join(root, "missing-ocsp")
			}
			data, e := json.Marshal(cfg)
			if e != nil {
				t.Fatal(e)
			}
			config := filepath.Join(root, "prepare.json")
			if e = os.WriteFile(config, data, 0600); e != nil {
				t.Fatal(e)
			}
			result, e := OperatorOperation(context.Background(), "prepare-role", config, "")
			if e != nil {
				t.Fatal("first preparation depended on not-yet-created secrets", e)
			}
			public := result.(map[string]string)
			role := mode
			if role == "ca" {
				role = "ca"
			}
			if !strings.HasPrefix(public[role], "age1") {
				t.Fatal("no public recipient returned")
			}
			if _, e = os.Stat(key); e != nil {
				t.Fatal(e)
			}
		})
	}
}
