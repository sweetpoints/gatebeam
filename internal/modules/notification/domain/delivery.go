package domain

import (
	"strings"
	"time"
)

type Channel struct {
	ID        string   `json:"id"`
	OwnerID   string   `json:"owner_id"`
	Revision  int64    `json:"revision"`
	Kind      string   `json:"kind"`
	Enabled   bool     `json:"enabled"`
	SiteIDs   []string `json:"site_ids"`
	System    bool     `json:"system"`
	Recipient string   `json:"recipient"`
	Host      string   `json:"host,omitempty"`
	Port      int      `json:"port,omitempty"`
	TLSMode   string   `json:"tls_mode,omitempty"`
	Username  string   `json:"username,omitempty"`
	From      string   `json:"from,omitempty"`
	Secret    []byte   `json:"-"`
}

func (c Channel) Validate() error {
	if (c.Kind != "telegram" && c.Kind != "smtp") || c.OwnerID == "" || len(c.SiteIDs) > 100 || c.System && len(c.SiteIDs) > 0 || !c.System && len(c.SiteIDs) == 0 {
		return ErrInvalid
	}
	for _, v := range []string{c.Recipient, c.Host, c.Username, c.From} {
		if len(v) > 320 || strings.ContainsAny(v, "\r\n\x00") {
			return ErrInvalid
		}
	}
	if c.Kind == "smtp" && (c.Host == "" || strings.ContainsAny(c.Host, " /:@") || c.Port < 1 || c.Port > 65535 || (c.TLSMode != "starttls" && c.TLSMode != "implicit") || c.From == "") {
		return ErrInvalid
	}
	return nil
}

type Delivery struct {
	ID, ChannelID, Status string
	Event                 Event
	Attempt               int
	Next                  time.Time
}

func RetryAfter(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		attempt = 6
	}
	return time.Duration(1<<attempt) * time.Second
}
