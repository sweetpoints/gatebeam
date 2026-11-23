// Package cloudflare implements only owned ACME TXT creation and cleanup.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var errRecordMissing = errors.New("owned TXT record absent")
var ErrDNS = errors.New("Cloudflare challenge operation failed")

type Zone struct {
	CredentialID       string
	CredentialRevision int64
	ID, Name           string
	Token              []byte
}
type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Comment string `json:"comment"`
	TTL     int    `json:"ttl"`
}
type owned struct {
	zone   Zone
	record record
}
type DNS struct {
	journal app.ChallengeJournal
	base    string
	client  *http.Client
	zones   []Zone
	owner   string
	mu      sync.Mutex
	records map[string]owned
}

func NewDNS(base string, client *http.Client, zones []Zone, owner string, journal ...app.ChallengeJournal) (*DNS, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || client == nil || len(zones) < 1 || len(zones) > 20 || owner == "" {
		return nil, ErrDNS
	}
	for _, z := range zones {
		if len(z.ID) != 32 || strings.Trim(z.ID, "0123456789abcdef") != "" || z.Name == "" || strings.ContainsAny(z.Name, "/*? \r\n") || len(z.Token) == 0 {
			return nil, ErrDNS
		}
	}
	c := *client
	c.Timeout = 5 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	zs := append([]Zone{}, zones...)
	sort.Slice(zs, func(i, j int) bool { return len(zs[i].Name) > len(zs[j].Name) })
	out := &DNS{base: strings.TrimSuffix(base, "/"), client: &c, zones: zs, owner: owner, records: map[string]owned{}}
	if len(journal) > 0 {
		out.journal = journal[0]
	}
	return out, nil
}
func (d *DNS) Timeout() (time.Duration, time.Duration) { return 45 * time.Second, time.Second }
func (d *DNS) zone(name string) (Zone, error) {
	for _, z := range d.zones {
		if name == z.Name || strings.HasSuffix(name, "."+z.Name) {
			return z, nil
		}
	}
	return Zone{}, ErrDNS
}
func challenge(domain, key string) (string, string, string) {
	name := "_acme-challenge." + strings.TrimPrefix(strings.TrimSuffix(domain, "."), "*.")
	sum := sha256.Sum256([]byte(key))
	value := base64.RawURLEncoding.EncodeToString(sum[:])
	binding := sha256.Sum256([]byte(name + "\x00" + value))
	return name, value, hex.EncodeToString(binding[:])
}
func (d *DNS) request(ctx context.Context, z Zone, method, path string, body any, result any) error {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return ErrDNS
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, d.base+"/zones/"+z.ID+"/dns_records"+path, bytes.NewReader(data))
	if e != nil {
		return ErrDNS
	}
	req.Header.Set("Authorization", "Bearer "+string(z.Token))
	req.Header.Set("Content-Type", "application/json")
	response, e := d.client.Do(req)
	if e != nil {
		return ErrDNS
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && method == http.MethodGet && strings.HasPrefix(path, "/") {
		return errRecordMissing
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return ErrDNS
	}
	data, e = io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(data) > 65536 {
		return ErrDNS
	}
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if json.Unmarshal(data, &envelope) != nil || !envelope.Success {
		return ErrDNS
	}
	if result != nil && json.Unmarshal(envelope.Result, result) != nil {
		return ErrDNS
	}
	return nil
}
func (d *DNS) Present(ctx context.Context, domain, token, key string) error {
	name, value, binding := challenge(domain, key)
	z, e := d.zone(name)
	if e != nil {
		return e
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.records[binding]; ok {
		return nil
	}
	r := record{Type: "TXT", Name: name, Content: value, Comment: "gatebeam-acme:" + d.owner + ":" + binding, TTL: 60}
	var created record
	receipt := app.ChallengeReceipt{Owner: d.owner, Binding: binding, CredentialID: z.CredentialID, CredentialRevision: z.CredentialRevision, ZoneID: z.ID, ZoneName: z.Name, Name: r.Name, Content: r.Content, Comment: r.Comment}
	if d.journal != nil {
		if e = d.journal.Save(ctx, receipt); e != nil {
			return e
		}
	}
	if e = d.request(ctx, z, http.MethodPost, "", r, &created); e != nil {
		return e
	}
	if created.ID == "" || strings.ContainsAny(created.ID, "/?. ") || created.Type != r.Type || created.Name != r.Name || created.Content != r.Content || created.Comment != r.Comment {
		return ErrDNS
	}
	d.records[binding] = owned{z, created}
	if d.journal != nil {
		receipt.RecordID = created.ID
		if e = d.journal.Save(ctx, receipt); e != nil {
			return e
		}
	}
	return nil
}
func (d *DNS) CleanUp(ctx context.Context, domain, token, key string) error {
	_, _, binding := challenge(domain, key)
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.records[binding]
	if !ok {
		return nil
	}
	// Verify exact immutable ownership before deletion; never enumerate/delete by name.
	var current record
	if e := d.request(ctx, v.zone, http.MethodGet, "/"+v.record.ID, nil, &current); e != nil {
		if errors.Is(e, errRecordMissing) {
			delete(d.records, binding)
			if d.journal != nil {
				return d.journal.Complete(ctx, d.owner, binding)
			}
			return nil
		}
		return e
	}
	if current.ID != v.record.ID || current.Type != "TXT" || current.Name != v.record.Name || current.Content != v.record.Content || current.Comment != v.record.Comment {
		return ErrDNS
	}
	if e := d.request(ctx, v.zone, http.MethodDelete, "/"+v.record.ID, nil, nil); e != nil {
		return e
	}
	delete(d.records, binding)
	if d.journal != nil {
		return d.journal.Complete(ctx, d.owner, binding)
	}
	return nil
}

// Recover deletes only records whose server-side owner marker and complete TXT
// value match a durable receipt. A lost POST response is resolved by exact marker
// filtering; no unrelated record at the challenge name may be removed.
func (d *DNS) Recover(ctx context.Context, r app.ChallengeReceipt) error {
	z, e := d.zone(r.Name)
	if e != nil || z.ID != r.ZoneID || d.owner != r.Owner {
		return ErrDNS
	}
	if r.RecordID == "" {
		var candidates []record
		query := "?type=TXT&name=" + url.QueryEscape(r.Name) + "&per_page=100"
		if e = d.request(ctx, z, http.MethodGet, query, nil, &candidates); e != nil {
			return e
		}
		if len(candidates) >= 100 {
			return ErrDNS
		}
		for _, v := range candidates {
			if v.Name == r.Name && v.Type == "TXT" && v.Content == r.Content && v.Comment == r.Comment {
				if r.RecordID != "" {
					return ErrDNS
				}
				r.RecordID = v.ID
			}
		}
		if r.RecordID == "" {
			if d.journal != nil {
				return d.journal.Complete(ctx, r.Owner, r.Binding)
			}
			return nil
		}
	}
	if strings.ContainsAny(r.RecordID, "/?. ") {
		return ErrDNS
	}
	d.records[r.Binding] = owned{z, record{ID: r.RecordID, Type: "TXT", Name: r.Name, Content: r.Content, Comment: r.Comment}}
	var current record
	if e = d.request(ctx, z, http.MethodGet, "/"+r.RecordID, nil, &current); e != nil {
		if errors.Is(e, errRecordMissing) {
			if d.journal != nil {
				return d.journal.Complete(ctx, r.Owner, r.Binding)
			}
			return nil
		}
		return e
	}
	if current.ID != r.RecordID || current.Type != "TXT" || current.Name != r.Name || current.Content != r.Content || current.Comment != r.Comment {
		return ErrDNS
	}
	if e = d.request(ctx, z, http.MethodDelete, "/"+r.RecordID, nil, nil); e != nil {
		return e
	}
	if d.journal != nil {
		return d.journal.Complete(ctx, r.Owner, r.Binding)
	}
	return nil
}
