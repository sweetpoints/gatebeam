package ocspcache_test

import (
	"fmt"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/modules/certificates/infrastructure/ocspcache"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheStoreRejectsUnsafeRecovery(t *testing.T) {
	for _, damage := range []string{"missing-floor", "floor-permissions", "response-symlink", "clock-rollback", "traversal"} {
		t.Run(damage, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "cache")
			store, err := ocspcache.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			key := strings.Repeat("a", 64)
			now := time.Now().UTC()
			if _, err = store.Check(t.Context(), key, now, false); err != nil {
				t.Fatal(err)
			}
			if err = store.Save(t.Context(), key, domain.CachedStatus{DER: []byte("signed DER owned by service"), ObservedAt: now}); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing-floor":
				if err = os.Remove(filepath.Join(root, "floor.json")); err != nil {
					t.Fatal(err)
				}
				if _, err = ocspcache.NewStore(root); err == nil {
					t.Fatal("missing revocation floor reset")
				}
			case "floor-permissions":
				if err = os.Chmod(filepath.Join(root, "floor.json"), 0644); err != nil {
					t.Fatal(err)
				}
				if _, err = ocspcache.NewStore(root); err == nil {
					t.Fatal("unprotected floor accepted")
				}
			case "response-symlink":
				path := filepath.Join(root, key+".json")
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(filepath.Join(root, "floor.json"), path); err != nil {
					t.Fatal(err)
				}
				if _, err = store.Load(t.Context(), key); err == nil {
					t.Fatal("symlink response accepted")
				}
			case "clock-rollback":
				if _, err = store.Check(t.Context(), key, now.Add(-time.Second), false); err == nil {
					t.Fatal("clock rolled back")
				}
			case "traversal":
				if err = store.Save(t.Context(), "../escape", domain.CachedStatus{DER: []byte("bad"), ObservedAt: now}); err == nil {
					t.Fatal("escaped cache root")
				}
			}
		})
	}
}

func TestCacheCapacityEvictsWithoutRemovingRevocationFloor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	store, err := ocspcache.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	revokedKey := strings.Repeat("b", 64)
	if _, err = store.Check(t.Context(), revokedKey, now, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1024; i++ {
		if err = os.WriteFile(filepath.Join(root, fmt.Sprintf("%064x.json", i)), []byte(`{"DER":"AA==","ObservedAt":"2026-11-08T00:00:00Z"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.Save(t.Context(), strings.Repeat("f", 64), domain.CachedStatus{DER: []byte("new signed response"), ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil || len(files) != 1026 {
		t.Fatalf("cache capacity not bounded: %d %v", len(files), err)
	}
	if revoked, err := store.Check(t.Context(), revokedKey, now, false); err != nil || !revoked {
		t.Fatal("eviction lost revocation floor")
	}
}

func TestCacheFloorCannotBeRolledBackIndependently(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	store, err := ocspcache.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	now := time.Now().UTC()
	if _, err = store.Check(t.Context(), key, now, false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "floor.json")
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Check(t.Context(), key, now.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.Check(t.Context(), key, now.Add(2*time.Second), false); err == nil && !revoked {
		t.Fatal("restored old floor resurrected good status")
	}
}

func TestCacheRecoversAbandonedAtomicWrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	store, err := ocspcache.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".status-abandoned")
	if err = os.WriteFile(path, make([]byte, 64<<10), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Check(t.Context(), strings.Repeat("a", 64), time.Now().UTC(), false); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("crashed writes accumulate outside bounded cache")
	}
}
