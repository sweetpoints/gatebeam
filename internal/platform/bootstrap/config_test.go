package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func configFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestConfigRejectsMissingSecrets(t *testing.T) {
	for _, body := range []string{`{"environment":"production","mode":"api"}`, `{"environment":"production","mode":"ca","identity_file":"missing","ca_signer_file":"missing"}`} {
		if _, err := Load(configFile(t, body)); err == nil {
			t.Fatal("missing secrets accepted")
		}
	}
}
func TestConfigModeIsolationAndValidation(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	body := `{"environment":"production","mode":"api","database_file":"` + identity + `","identity_file":"` + identity + `"}`
	if _, err := Load(configFile(t, body)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"environment":"oops","mode":"api"}`, `{"environment":"development","mode":"oops"}`, `{"environment":"development","mode":"api","unknown":true}`, `{} {}`} {
		if _, err := Load(configFile(t, body)); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

func TestDatabaseModeReferences(t *testing.T) {
	for _, mode := range []string{"api", "worker", "ca", "migrate", "bootstrap", "edge"} {
		if _, err := Load(configFile(t, `{"environment":"development","mode":"`+mode+`"}`)); err == nil {
			t.Fatalf("%s accepted no database", mode)
		}
	}

}

func TestProductionMigrateNeedsOnlyDatabaseSecret(t *testing.T) {
	database := filepath.Join(t.TempDir(), "database")
	if e := os.WriteFile(database, []byte("test-dsn"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(configFile(t, `{"environment":"production","mode":"migrate","database_file":"`+database+`"}`)); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(configFile(t, `{"environment":"production","mode":"migrate","database_file":"missing"}`)); e == nil {
		t.Fatal("missing database accepted")
	}
}

func TestBootstrapRequiresReferencesButAllowsNewIdentity(t *testing.T) {
	database := filepath.Join(t.TempDir(), "database")
	if e := os.WriteFile(database, []byte("dsn"), 0600); e != nil {
		t.Fatal(e)
	}
	identity := filepath.Join(t.TempDir(), "new-identity")
	if _, e := Load(configFile(t, `{"environment":"production","mode":"bootstrap","database_file":"`+database+`","identity_file":"`+identity+`"}`)); e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{`{"environment":"development","mode":"bootstrap"}`, `{"environment":"production","mode":"bootstrap","database_file":"` + database + `"}`} {
		if _, e := Load(configFile(t, body)); e == nil {
			t.Fatal("bootstrap missing references accepted")
		}
	}
}

func TestProductionWorkerNeedsDatabaseWithoutIdentityKey(t *testing.T) {
	database := filepath.Join(t.TempDir(), "database")
	if e := os.WriteFile(database, []byte("dsn"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(configFile(t, `{"environment":"production","mode":"worker","database_file":"`+database+`"}`)); e != nil {
		t.Fatal(e)
	}
}

func TestHistoryProcessCapabilityIsolation(t *testing.T) {
	for _, c := range []Config{{DatabaseFile: "db"}, {IdentityFile: "seed"}, {CASignerFile: "signer"}, {CertificateIdentityFile: "cert"}, {CertificateProviderIdentityFile: "provider"}, {CertificateStatusProfilesFile: "status"}, {CATLSKeyFile: "tls"}, {ManagementKeyFile: "key"}, {ArchiveCredentialsFile: "archive"}, {ACMEWebRoot: "webroot"}, {CARootFile: "root"}} {
		if ValidateCapabilities("query", c) == nil {
			t.Fatalf("query accepted forbidden capability: %+v", c)
		}
	}
	for _, mode := range []string{"api", "edge", "ca"} {
		if ValidateCapabilities(mode, Config{QueryCredentialsFile: "r2"}) == nil {
			t.Fatal("query credential escaped", mode)
		}
		if ValidateCapabilities(mode, Config{ArchiveCredentialsFile: "r2"}) == nil {
			t.Fatal("archive credential escaped", mode)
		}
	}
	if ValidateCapabilities("api", Config{QuerySocket: "socket"}) == nil {
		t.Fatal("API executor accepted")
	}
	if _, e := Load(configFile(t, `{"environment":"development","mode":"query"}`)); e != nil {
		t.Fatal("query incorrectly requires DB", e)
	}
}

func TestNotificationIdentityOnlyWorkerCapability(t *testing.T) {
	for _, mode := range []string{"api", "edge", "ca", "query", "migrate", "bootstrap"} {
		if ValidateCapabilities(mode, Config{NotificationIdentityFile: "worker.agekey"}) == nil {
			t.Fatal("notification identity allowed in", mode)
		}
	}
	if e := ValidateCapabilities("worker", Config{NotificationIdentityFile: "worker.agekey"}); e != nil {
		t.Fatal(e)
	}
}

func TestRoleMigrationIsExplicitCapability(t *testing.T) {
	for _, mode := range []string{"api", "edge", "worker", "ca", "query", "bootstrap", "backup-export", "backup-restore"} {
		if ValidateCapabilities(mode, Config{MigrateRoles: true}) == nil {
			t.Fatalf("%s accepted migration-only authority", mode)
		}
	}
	if err := ValidateCapabilities("migrate", Config{MigrateRoles: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configFile(t, `{"environment":"development","mode":"migrate","database_file":"migration-secret","migrate_roles":true}`))
	if err != nil || !cfg.MigrateRoles {
		t.Fatalf("explicit migration configuration not accepted: %v", err)
	}
}

func TestOfflineEdgeLoadDoesNotReadDatabaseSecret(t *testing.T) {
	for _, database := range []string{"", filepath.Join(t.TempDir(), "unreadable-database")} {
		body := `{"environment":"production","mode":"edge","runtime_protocol":1,"node_id":"11111111-1111-4111-8111-111111111111","node_epoch":1,"edge_root":"/runtime","database_file":"` + database + `"}`
		if _, err := Load(configFile(t, body)); err != nil {
			t.Fatalf("offline edge load depends on database: %v", err)
		}
	}
}

func TestRuntimeProtocolRequiresExplicitStableNode(t *testing.T) {
	for _, fields := range []string{`"runtime_protocol":2`, `"runtime_protocol":1`, `"runtime_protocol":1,"node_id":"not-a-node","node_epoch":1`, `"runtime_protocol":1,"node_id":"11111111-1111-4111-8111-111111111111","node_epoch":0`} {
		if _, err := Load(configFile(t, `{"environment":"development","mode":"edge","database_file":"preconfigured",`+fields+`}`)); err == nil {
			t.Fatal("invalid node protocol accepted")
		}
	}
}
