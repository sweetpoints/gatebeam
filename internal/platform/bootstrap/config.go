// Package bootstrap loads explicit process configuration without environment secrets.
package bootstrap

import (
	"encoding/json"
	"errors"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/secrets"
	"github.com/google/uuid"
	"io"
	"os"
)

type PrivateTLSRenewal struct {
	Origin             string `json:"origin"`
	Email              string `json:"email"`
	EABFile            string `json:"eab_file"`
	TrustFile          string `json:"trust_file"`
	CheckSeconds       int    `json:"check_seconds,omitempty"`
	RenewBeforeSeconds int    `json:"renew_before_seconds,omitempty"`
}
type Config struct {
	PrivateTLSRenewal                  *PrivateTLSRenewal           `json:"private_tls_renewal,omitempty"`
	LogRotateBytes                     int64                        `json:"log_rotate_bytes,omitempty"`
	LogMaxBytes                        int64                        `json:"log_max_bytes,omitempty"`
	LogMaxFiles                        int                          `json:"log_max_files,omitempty"`
	HealthEndpoints                    map[string]map[string]string `json:"health_endpoints,omitempty"`
	APITLSClientNames                  []string                     `json:"api_tls_client_names,omitempty"`
	RuntimeState                       *lifecycle.State             `json:"-"`
	ManagementAPIPeerAddress           string                       `json:"management_api_peer_address,omitempty"`
	ManagementAPIName                  string                       `json:"management_api_name,omitempty"`
	ManagementAPITrustFile             string                       `json:"management_api_trust_file,omitempty"`
	ManagementAPIClientCertificateFile string                       `json:"management_api_client_certificate_file,omitempty"`
	ManagementAPIClientKeyFile         string                       `json:"management_api_client_key_file,omitempty"`
	ManagementAPIStateFile             string                       `json:"management_api_state_file,omitempty"`
	APITLSCertificateFile              string                       `json:"api_tls_certificate_file,omitempty"`
	APITLSKeyFile                      string                       `json:"api_tls_key_file,omitempty"`
	APITLSCRLFile                      string                       `json:"api_tls_crl_file,omitempty"`
	APITLSStateFile                    string                       `json:"api_tls_state_file,omitempty"`
	APITLSTrustFile                    string                       `json:"api_tls_trust_file,omitempty"`
	HealthListen                       string                       `json:"health_listen,omitempty"`
	ControlSocket                      string                       `json:"control_socket,omitempty"`
	DrainSeconds                       int                          `json:"drain_seconds,omitempty"`
	EncryptionRecipients               secrets.RolePolicy           `json:"encryption_recipients,omitempty"`
	ImageDigest                        string                       `json:"image_digest"`
	NodeID                             string                       `json:"node_id"`
	NodeEpoch                          uint64                       `json:"node_epoch"`
	RuntimeProtocol                    uint32                       `json:"runtime_protocol"`
	MigrateRoles                       bool                         `json:"migrate_roles"`
	CAImportDirectory                  string                       `json:"ca_import_directory"`
	RecoveryReportDirectory            string                       `json:"recovery_report_directory"`
	BackupRecipient                    string                       `json:"backup_recipient"`
	BackupEpoch                        string                       `json:"backup_epoch"`
	BackupCapsuleDirectory             string                       `json:"backup_capsule_directory"`
	BackupSpoolDirectory               string                       `json:"backup_spool_directory"`
	BackupCredentialsFile              string                       `json:"backup_credentials_file"`
	BackupRetentionDays                int                          `json:"backup_retention_days"`
	BackupMaxAgeMinutes                int                          `json:"backup_max_age_minutes"`
	RecoverySource                     string                       `json:"recovery_source"`
	RecoveryIdentityFile               string                       `json:"recovery_identity_file"`
	RecoveryDirectory                  string                       `json:"recovery_directory"`

	NotificationRecipient             string   `json:"notification_recipient"`
	NotificationIdentityFile          string   `json:"notification_identity_file"`
	ArchiveCredentialsFile            string   `json:"archive_credentials_file"`
	QueryCredentialsFile              string   `json:"query_credentials_file"`
	QuerySocket                       string   `json:"query_socket"`
	LogDirectory                      string   `json:"log_directory"`
	QueryLocalDirectory               string   `json:"query_local_directory"`
	LogSpoolDirectory                 string   `json:"log_spool_directory"`
	CertificateACMETransportTrustFile string   `json:"certificate_acme_transport_trust_file"`
	CertificateProviderIdentityFile   string   `json:"certificate_provider_identity_file"`
	CertificateProviderRecipient      string   `json:"certificate_provider_recipient"`
	CertificateIdentityFile           string   `json:"certificate_identity_file"`
	CertificateRecipient              string   `json:"certificate_recipient"`
	CertificateStatusProfilesFile     string   `json:"certificate_status_profiles_file"`
	ACMEWebRoot                       string   `json:"acme_webroot"`
	CARootOCSPCertificateFile         string   `json:"ca_root_ocsp_certificate_file"`
	CARootOCSPSignerFile              string   `json:"ca_root_ocsp_signer_file"`
	CAStatusOrigin                    string   `json:"ca_status_origin"`
	CAStatusListen                    string   `json:"ca_status_listen"`
	CARootCRLFile                     string   `json:"ca_root_crl_file"`
	CAOrigin                          string   `json:"ca_origin"`
	CARecipient                       string   `json:"ca_recipient"`
	CAIdentityFile                    string   `json:"ca_identity_file"`
	CACertificateFile                 string   `json:"ca_certificate_file"`
	CARootFile                        string   `json:"ca_root_file"`
	CAListen                          string   `json:"ca_listen"`
	CAHostname                        string   `json:"ca_hostname"`
	CATLSCertificateFile              string   `json:"ca_tls_certificate_file"`
	CATLSKeyFile                      string   `json:"ca_tls_key_file"`
	CAValidationNetworks              []string `json:"ca_validation_networks"`
	CAValidationDenyNetworks          []string `json:"ca_validation_deny_networks"`
	CAServerNames                     []string `json:"ca_server_names"`
	CAClientNames                     []string `json:"ca_client_names"`
	OfflineRootDirectory              string   `json:"offline_root_directory"`
	CAOutputDirectory                 string   `json:"ca_output_directory"`
	CARootName                        string   `json:"ca_root_name"`
	CAIntermediateName                string   `json:"ca_intermediate_name"`

	APIPrivateNetwork         string   `json:"api_private_network"`
	EdgeRoot                  string   `json:"edge_root"`
	ManagementAddress         string   `json:"management_address"`
	ManagementDomain          string   `json:"management_domain"`
	ManagementAPIAddress      string   `json:"management_api_address"`
	ManagementCertificateFile string   `json:"management_certificate_file"`
	ManagementKeyFile         string   `json:"management_key_file"`
	ManagementTrustFile       string   `json:"management_trust_file"`
	ProtectedNetworks         []string `json:"protected_networks"`

	DatabaseFile      string `json:"database_file"`
	Environment       string `json:"environment"`
	Mode              string `json:"mode"`
	IdentityFile      string `json:"identity_file"`
	CASignerFile      string `json:"ca_signer_file"`
	APIListen         string `json:"api_listen"`
	APIOrigin         string `json:"api_origin"`
	HTTPSGatewayReady bool   `json:"https_gateway_ready"`
	AdminName         string `json:"admin_name"`
}

func SupportedMode(mode string) bool {
	switch mode {
	case "api", "worker", "edge", "ca", "query", "bootstrap", "migrate", "ca-bootstrap", "ca-import", "backup-export", "backup-restore":
		return true
	}
	return false
}
func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("configuration unavailable")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil {
		return Config{}, errors.New("invalid configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Config{}, errors.New("invalid configuration")
	}
	if (cfg.Environment != "production" && cfg.Environment != "development") || !SupportedMode(cfg.Mode) {
		return Config{}, errors.New("invalid environment or mode")
	}
	if err := secrets.ValidateRoleRecipients(cfg.EncryptionRecipients); err != nil {
		return Config{}, errors.New("invalid role recipient policy")
	}
	if err := ValidateCapabilities(cfg.Mode, cfg); err != nil {
		return Config{}, err
	}
	if cfg.DatabaseFile == "" && ((cfg.Mode == "edge" && cfg.RuntimeProtocol == 0) || cfg.Mode == "api" || cfg.Mode == "worker" || cfg.Mode == "ca" || cfg.Mode == "migrate" || cfg.Mode == "bootstrap") {
		return Config{}, errors.New("database secret reference required")
	}
	if cfg.Mode == "bootstrap" && cfg.IdentityFile == "" {
		return Config{}, errors.New("identity path required")
	}
	if cfg.Environment == "production" {
		paths := []string{}
		if cfg.Mode != "migrate" && cfg.Mode != "bootstrap" && cfg.Mode != "edge" && cfg.Mode != "worker" && cfg.Mode != "ca" && cfg.Mode != "ca-bootstrap" && cfg.Mode != "ca-import" && cfg.Mode != "query" && cfg.Mode != "backup-export" && cfg.Mode != "backup-restore" {
			paths = append(paths, cfg.IdentityFile)
		}
		if cfg.DatabaseFile != "" && !(cfg.Mode == "edge" && cfg.RuntimeProtocol == 1) {
			paths = append(paths, cfg.DatabaseFile)
		}
		if cfg.Mode == "ca" {
			paths = append(paths, cfg.CASignerFile, cfg.CAIdentityFile, cfg.CARootOCSPSignerFile)
		}
		for _, p := range paths {
			f, err := os.Open(p)
			if err != nil {
				return Config{}, errors.New("required secret unavailable")
			}
			info, err := f.Stat()
			f.Close()
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				return Config{}, errors.New("required secret unavailable")
			}
		}
	}
	return cfg, nil
}

// ValidateCapabilities is checked both on file load and by process assembly.
func ValidateCapabilities(mode string, cfg Config) error {
	if v := cfg.PrivateTLSRenewal; v != nil {
		if (mode != "api" && mode != "ca" && mode != "edge") || v.Origin == "" || v.Email == "" || v.EABFile == "" || v.TrustFile == "" || v.CheckSeconds < 0 || v.CheckSeconds > 3600 || v.RenewBeforeSeconds < 0 || v.RenewBeforeSeconds > 31*86400 {
			return errors.New("invalid private role renewal policy")
		}
	}

	if (cfg.APITLSCRLFile != "" || cfg.APITLSStateFile != "" || cfg.APITLSCertificateFile != "" || cfg.APITLSKeyFile != "" || cfg.APITLSTrustFile != "" || len(cfg.APITLSClientNames) > 0) && mode != "api" {
		return errors.New("private API server identity forbidden")
	}
	if (cfg.ManagementAPIClientKeyFile != "" || cfg.ManagementAPIClientCertificateFile != "" || cfg.ManagementAPITrustFile != "" || cfg.ManagementAPIStateFile != "") && mode != "edge" {
		return errors.New("management upstream capability forbidden")
	}
	if cfg.DrainSeconds < 0 || cfg.DrainSeconds > 300 {
		return errors.New("invalid drain deadline")
	}

	if cfg.RuntimeProtocol > 1 {
		return errors.New("unsupported runtime protocol")
	}
	if cfg.RuntimeProtocol == 1 || cfg.NodeID != "" || cfg.NodeEpoch != 0 {
		id, err := uuid.Parse(cfg.NodeID)
		if err != nil || id == uuid.Nil || id.String() != cfg.NodeID || cfg.NodeEpoch == 0 || cfg.NodeEpoch > 1<<63-1 {
			return errors.New("stable node identity required")
		}
	}
	if cfg.MigrateRoles && mode != "migrate" {
		return errors.New("role migration capability forbidden")
	}
	if cfg.CAImportDirectory != "" && mode != "ca-import" {
		return errors.New("offline CA import source forbidden online")
	}
	if mode == "ca-import" && (cfg.DatabaseFile != "" || cfg.OfflineRootDirectory != "" || cfg.IdentityFile != "" || cfg.CertificateIdentityFile != "" || cfg.CertificateProviderIdentityFile != "") {
		return errors.New("CA import must be offline with no runtime credentials")
	}
	if cfg.QueryLocalDirectory != "" && mode != "query" {
		return errors.New("query local capability forbidden")
	}
	if cfg.RecoveryReportDirectory != "" && mode != "api" && mode != "backup-restore" {
		return errors.New("recovery report capability forbidden")
	}
	if cfg.RecoveryIdentityFile != "" && mode != "backup-restore" {
		return errors.New("offline recovery identity forbidden online")
	}
	if cfg.BackupCredentialsFile != "" && mode != "worker" {
		return errors.New("backup upload credentials forbidden")
	}
	if mode == "backup-export" || mode == "backup-restore" {
		if cfg.IdentityFile != "" || cfg.CASignerFile != "" || cfg.CAIdentityFile != "" || cfg.CARootOCSPSignerFile != "" || cfg.CATLSKeyFile != "" || cfg.ManagementKeyFile != "" || cfg.CertificateIdentityFile != "" || cfg.CertificateProviderIdentityFile != "" || cfg.NotificationIdentityFile != "" || cfg.OfflineRootDirectory != "" || cfg.ArchiveCredentialsFile != "" || cfg.QueryCredentialsFile != "" {
			return errors.New("local backup command includes online private key capability")
		}
	}

	if cfg.NotificationIdentityFile != "" && mode != "worker" {
		return errors.New("notification secret capability forbidden")
	}
	if cfg.ArchiveCredentialsFile != "" && mode != "worker" || cfg.QueryCredentialsFile != "" && mode != "query" {
		return errors.New("history credential capability forbidden")
	}
	if mode == "api" && cfg.QuerySocket != "" {
		return errors.New("API query executor capability forbidden")
	}
	if mode == "query" && (cfg.DatabaseFile != "" || cfg.IdentityFile != "" || cfg.CertificateIdentityFile != "" || cfg.CertificateProviderIdentityFile != "" || cfg.CATLSKeyFile != "" || cfg.ManagementKeyFile != "" || cfg.CertificateStatusProfilesFile != "" || cfg.ACMEWebRoot != "" || cfg.CARootFile != "" || cfg.CACertificateFile != "" || cfg.CARootOCSPCertificateFile != "" || cfg.CARootCRLFile != "" || cfg.LogDirectory != "" || cfg.LogSpoolDirectory != "") {
		return errors.New("query process capability forbidden")
	}

	if mode != "ca" && (cfg.CASignerFile != "" || cfg.CAIdentityFile != "" || cfg.CARootOCSPSignerFile != "") {
		return errors.New("CA signing configuration forbidden for this process")
	}
	if mode != "ca-bootstrap" && mode != "ca-import" && (cfg.OfflineRootDirectory != "" || cfg.CAOutputDirectory != "") {
		return errors.New("offline CA ceremony configuration forbidden for this process")
	}
	if mode == "ca" && cfg.IdentityFile != "" {
		return errors.New("CA requires its dedicated identity file")
	}
	return nil
}
