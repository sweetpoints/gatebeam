package bootstrap

import "testing"

func TestOfflineCeremonyModeDoesNotNeedDatabase(t *testing.T) {
	if _, e := Load(configFile(t, `{"environment":"development","mode":"ca-bootstrap","offline_root_directory":"/offline","ca_output_directory":"/online","ca_root_name":"owned root","ca_intermediate_name":"owned intermediate"}`)); e != nil {
		t.Fatal(e)
	}
}
func TestAPICannotConfigureCASecrets(t *testing.T) {
	for _, field := range []string{"ca_signer_file", "ca_identity_file", "ca_root_ocsp_signer_file", "offline_root_directory"} {
		if _, e := Load(configFile(t, `{"environment":"development","mode":"api","database_file":"db","`+field+`":"forbidden"}`)); e == nil {
			t.Fatal("API signer configuration accepted")
		}
	}
}
