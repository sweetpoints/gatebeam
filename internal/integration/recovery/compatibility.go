package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gatebeam/db/migrations"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/modules/backup/domain"
	"io/fs"
	"strconv"
	"strings"
)

const CurrentSchema int64 = 27

type Contract struct {
	Version int64
	Digest  string
	Tables  []string
}

var addedTables = map[string]int64{
	"deployment_nodes": 24, "deployment_desired": 24, "deployment_node_runtime": 24, "deployment_node_events": 24,
	"certificates_node_envelopes": 25, "certificates_http_challenges": 25, "certificates_http_targets": 25, "certificates_provider_envelopes": 25, "pki_eab_envelopes": 25,
	"observability_query_parts": 26, "deployment_upgrade_runs": 27,
}

// SchemaContract accepts only explicitly reviewed schemas. Each digest covers
// the original migration prefix; changing a previously shipped migration is a
// contract change and cannot silently authorize arbitrary backup input.
func SchemaContract(version int64) (Contract, error) {
	switch version {
	case 22, 23, 24, 25, 26, 27:
	default:
		return Contract{}, ErrRecovery
	}
	c := Contract{Version: version}
	h := sha256.New()
	entries, e := fs.Glob(migrations.Files, "*.sql")
	if e != nil {
		return Contract{}, ErrRecovery
	}
	for _, name := range entries {
		prefix, _, ok := strings.Cut(name, "_")
		v, e := strconv.ParseInt(prefix, 10, 64)
		if !ok || e != nil {
			return Contract{}, ErrRecovery
		}
		if v > version {
			continue
		}
		b, e := fs.ReadFile(migrations.Files, name)
		if e != nil {
			return Contract{}, ErrRecovery
		}
		h.Write([]byte(name))
		h.Write(b)
	}
	c.Digest = hex.EncodeToString(h.Sum(nil))
	for _, table := range tables {
		if addedTables[table] <= version {
			c.Tables = append(c.Tables, table)
		}
	}
	return c, nil
}
func RestoreCompatibility(source, target int64) error {
	if _, e := SchemaContract(source); e != nil {
		return e
	}
	if target != CurrentSchema {
		return ErrRecovery
	}
	return nil
}
func contractByDigest(digest string) (Contract, error) {
	for _, v := range []int64{22, 23, 24, 25, 26, 27} {
		c, e := SchemaContract(v)
		if e == nil && c.Digest == digest {
			return c, nil
		}
	}
	return Contract{}, ErrRecovery
}

// normalizeArchive applies only this reviewed additive conversion. It grants
// no authority; owner quarantine still runs before a restored database escapes.
func normalizeArchive(a application.Archive) (application.Archive, error) {
	source, e := contractByDigest(a.Manifest.Schema)
	if e != nil || RestoreCompatibility(source.Version, CurrentSchema) != nil {
		return application.Archive{}, ErrRecovery
	}
	out := a
	out.Files = make(map[string][]byte, len(tables)+len(a.Files))
	for name, b := range a.Files {
		out.Files[name] = b
	}
	for _, table := range tables {
		name := "database/" + table + ".json"
		if addedTables[table] > source.Version {
			out.Files[name] = []byte(`[]`)
			continue
		}
		defaults := map[string]json.RawMessage{}
		if source.Version < 23 && table == "jobs" {
			defaults["target_node_id"] = json.RawMessage(`null`)
			defaults["target_node_epoch"] = json.RawMessage(`null`)
		}
		if source.Version < 26 {
			switch table {
			case "observability_segments", "observability_batches", "observability_manifests", "observability_archive_objects":
				defaults["node_id"] = json.RawMessage(`"legacy"`)
			case "observability_queries":
				defaults["coverage"] = json.RawMessage(`""`)
				defaults["truncated"] = json.RawMessage(`false`)
			}
		}
		if len(defaults) == 0 {
			continue
		}
		var rows []map[string]json.RawMessage
		if json.Unmarshal(a.Files[name], &rows) != nil {
			return application.Archive{}, ErrRecovery
		}
		for _, row := range rows {
			for field, value := range defaults {
				if _, exists := row[field]; exists {
					return application.Archive{}, fmt.Errorf("%w: field outside source contract", ErrRecovery)
				}
				row[field] = value
			}
		}
		for _, row := range rows {
			raw, e := json.Marshal(row)
			if e != nil || !validSnapshotRow(raw) {
				return application.Archive{}, ErrRecovery
			}
		}
		raw, e := json.Marshal(rows)
		if e != nil || len(raw) > domain.MaxFile {
			return application.Archive{}, ErrRecovery
		}
		out.Files[name] = raw
	}
	total := 0
	for _, b := range out.Files {
		total += len(b)
		if total > domain.MaxArchive {
			return application.Archive{}, ErrRecovery
		}
	}
	return out, nil
}
