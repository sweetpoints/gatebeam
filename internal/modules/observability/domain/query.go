package domain

import (
	"errors"
	"strings"
	"time"
)

var ErrQueryTimeout = errors.New("query_timeout")
var ErrQueryBusy = errors.New("query_busy")

type QueryFilter struct {
	Source                  string `json:"source,omitempty"`
	SiteIDs                 []string
	From, To                time.Time
	Route, Method, ConfigID string
	Status                  int
}

func (f QueryFilter) Validate() error {
	if (f.Source != "" && f.Source != "archive" && f.Source != "local") || len(f.SiteIDs) < 1 || len(f.SiteIDs) > 100 || f.From.IsZero() || !f.From.Before(f.To) || f.To.Sub(f.From) > 31*24*time.Hour || f.Route != "" && !ValidRoute(f.Route) || f.Method != "" && !ValidMethod(f.Method) || f.Status != 0 && (f.Status < 100 || f.Status > 599) || f.ConfigID != "" && (len(f.ConfigID) != 64 || strings.Trim(f.ConfigID, "0123456789abcdef") != "") {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, s := range f.SiteIDs {
		if !ValidSite(s) || seen[s] {
			return ErrInvalid
		}
		seen[s] = true
	}
	return nil
}

// QueryRow deliberately contains only standard access-log fields.
type QueryRow struct {
	NodeID    string `json:"node_id,omitempty"`
	Time      string `json:"time"`
	SiteID    string `json:"site_id"`
	RequestID string `json:"request_id"`
	Route     string `json:"route"`
	Method    string `json:"method"`
	Status    int    `json:"status"`
	Bytes     int64  `json:"bytes_sent"`
	Micros    int64  `json:"request_micros"`
	ConfigID  string `json:"config_id"`
}
