package cloudflare_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/cloudflare"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentDNSTXTOnlyCleansOwnRecords(t *testing.T) {
	var mu sync.Mutex
	records := map[string]map[string]any{"other": {"type": "TXT", "name": "_acme-challenge.entry.test", "content": "other-value", "comment": "other-owner"}}
	next := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer owned-token" {
			http.Error(w, "denied", 403)
			return
		}
		switch r.Method {
		case "POST":
			var v map[string]any
			if json.NewDecoder(r.Body).Decode(&v) != nil {
				t.Error("body")
			}
			next++
			id := fmt.Sprint(next)
			v["id"] = id
			records[id] = v
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v})
		case "GET":
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			if v, ok := records[id]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v})
			} else {
				http.NotFound(w, r)
			}
		case "DELETE":
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			delete(records, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": id}})
		default:
			t.Error("unexpected method", r.Method)
		}
	}))
	defer server.Close()
	zone := cloudflare.Zone{ID: strings.Repeat("a", 32), Name: "entry.test", Token: []byte("owned-token")}
	first, e := cloudflare.NewDNS(server.URL, server.Client(), []cloudflare.Zone{zone}, "writer-one")
	if e != nil {
		t.Fatal(e)
	}
	second, e := cloudflare.NewDNS(server.URL, server.Client(), []cloudflare.Zone{zone}, "writer-two")
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if e = first.Present(ctx, "entry.test", "token1", "key1"); e != nil {
		t.Fatal(e)
	}
	if e = second.Present(ctx, "entry.test", "token2", "key2"); e != nil {
		t.Fatal(e)
	}
	if e = first.CleanUp(ctx, "entry.test", "token1", "key1"); e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	if len(records) != 2 || records["other"] == nil {
		t.Fatal("cleaned another challenge", records)
	}
	mu.Unlock()
	if e = second.CleanUp(ctx, "entry.test", "token2", "key2"); e != nil {
		t.Fatal(e)
	}
	if e = first.Present(ctx, "unauthorized.test", "token", "key"); e == nil {
		t.Fatal("unauthorized zone accepted")
	}
}

type receiptJournal struct {
	receipt   app.ChallengeReceipt
	failID    bool
	completed bool
}

func (j *receiptJournal) Save(_ context.Context, r app.ChallengeReceipt) error {
	if j.failID && r.RecordID != "" {
		return errors.New("owned database outage after POST")
	}
	j.receipt = r
	return nil
}
func (j *receiptJournal) Complete(context.Context, string, string) error {
	j.completed = true
	return nil
}
func (j *receiptJournal) Pending(context.Context) ([]app.PendingChallenge, error) { return nil, nil }
func TestRestartCleanupLostPostAndTamperedOwnership(t *testing.T) {
	for _, mode := range []string{"lost-post", "tampered", "already-deleted"} {
		t.Run(mode, func(t *testing.T) {
			records := map[string]map[string]any{"unrelated": {"id": "unrelated", "type": "TXT", "name": "_acme-challenge.entry.test", "content": "different", "comment": "someone-else"}}
			deleted := []string{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				result := any(nil)
				switch r.Method {
				case "POST":
					var v map[string]any
					_ = json.NewDecoder(r.Body).Decode(&v)
					v["id"] = "owned"
					records["owned"] = v
					result = v
				case "GET":
					if r.URL.Query().Get("type") == "TXT" {
						values := []map[string]any{}
						for _, v := range records {
							values = append(values, v)
						}
						result = values
					} else {
						id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
						v, ok := records[id]
						if !ok {
							http.NotFound(w, r)
							return
						}
						result = v
					}
				case "DELETE":
					id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
					deleted = append(deleted, id)
					delete(records, id)
					result = map[string]string{"id": id}
				default:
					t.Error("unexpected method")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
			}))
			defer server.Close()
			zone := cloudflare.Zone{ID: strings.Repeat("a", 32), Name: "entry.test", Token: []byte("owned-token")}
			journal := &receiptJournal{failID: mode == "lost-post"}
			first, e := cloudflare.NewDNS(server.URL, server.Client(), []cloudflare.Zone{zone}, "durable-owner", journal)
			if e != nil {
				t.Fatal(e)
			}
			e = first.Present(context.Background(), "entry.test", "token", "key-authorization")
			if mode == "lost-post" && (e == nil || journal.receipt.RecordID != "") {
				t.Fatal("lost POST not simulated", e)
			}
			if mode != "lost-post" && e != nil {
				t.Fatal(e)
			}
			if mode == "tampered" {
				records["owned"]["comment"] = "another-owner"
			}
			if mode == "already-deleted" {
				delete(records, "owned")
			}
			restarted, e := cloudflare.NewDNS(server.URL, server.Client(), []cloudflare.Zone{zone}, "durable-owner", journal)
			if e != nil {
				t.Fatal(e)
			}
			e = restarted.Recover(context.Background(), journal.receipt)
			if mode == "tampered" {
				if e == nil || len(deleted) != 0 || journal.completed {
					t.Fatal("tampered ownership was cleaned")
				}
			} else {
				if e != nil || !journal.completed || records["owned"] != nil || records["unrelated"] == nil {
					t.Fatal("restart cleanup failed", e, deleted)
				}
			}
		})
	}
}
