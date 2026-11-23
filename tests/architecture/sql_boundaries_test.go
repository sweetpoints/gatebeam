package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SQL ownership is checked independently of Go imports. Migrations establish
// the table inventory; every literal reference in a module's SQL/Go adapter
// must belong to that context. Integration recovery is deliberately outside
// modules and has its own role/transaction acceptance.
func TestModuleSQLReferencesOwnedTables(t *testing.T) {
	root := filepath.Join("..", "..")
	create := regexp.MustCompile(`(?i)CREATE TABLE\s+([a-z][a-z0-9_]*)`)
	owners := map[string]string{}
	migrations, err := filepath.Glob(filepath.Join(root, "db", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range migrations {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range create.FindAllStringSubmatch(string(b), -1) {
			table := strings.ToLower(m[1])
			owner, _, ok := strings.Cut(table, "_")
			if !ok || table == "job_attempts" || table == "consumer_receipts" {
				owner = "platform"
			}
			owners[table] = owner
		}
	}
	if len(owners) < 40 {
		t.Fatal("migration table inventory incomplete")
	}
	// Explicit platform-owned persistence contracts: fixed execution status
	// projection and transactional observability event append. No general foreign
	// business-table exemption is allowed.
	platformContracts := map[string]map[string]bool{
		"deployment/infrastructure/postgres/operations.go": {"jobs": true},
		"observability/infrastructure/postgres/history.go": {"outbox": true},
		"observability/infrastructure/postgres/store.go":   {"outbox": true},
	}
	references := regexp.MustCompile(`(?i)\b(?:FROM|JOIN|UPDATE|INTO|TABLE|REFERENCES)\s+([a-z][a-z0-9_]*)`)
	err = filepath.WalkDir(filepath.Join(root, "internal", "modules"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(path, "_test.go") || !(strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".sql")) {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Join(root, "internal", "modules"), path)
		module := strings.Split(filepath.ToSlash(rel), "/")[0]
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range references.FindAllStringSubmatch(string(b), -1) {
			table := strings.ToLower(m[1])
			if owner, ok := owners[table]; ok && owner != module && !platformContracts[filepath.ToSlash(rel)][table] {
				t.Errorf("%s references %s owned by %s", rel, table, owner)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
