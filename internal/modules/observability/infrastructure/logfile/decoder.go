package logfile

import (
	"encoding/json"
	"gatebeam/internal/modules/observability/domain"
	"strconv"
	"time"
)

// decode accepts the native Nginx log wire format. Unknown legacy fields are
// discarded here; only typed allowlisted values enter the domain constructor.
func decode(line []byte) (domain.Event, string) {
	var raw struct {
		Schema         int    `json:"schema_version"`
		Site           string `json:"site_id"`
		Request        string `json:"request_id"`
		Time           string `json:"time"`
		Route          string `json:"route"`
		Method         string `json:"method"`
		Status         int    `json:"status"`
		Bytes          int64  `json:"bytes_sent"`
		Latency        string `json:"request_time"`
		Pattern        string `json:"path_pattern"`
		Config         string `json:"config_id"`
		Target         string `json:"target_id"`
		Outcome        string `json:"upstream_outcome"`
		RateRequest    string `json:"rate_req"`
		RateConnection string `json:"rate_conn"`
	}

	if len(line) > domain.MaxLine || json.Unmarshal(line, &raw) != nil {
		return domain.Event{}, "invalid"
	}
	if raw.Schema != 1 {
		return domain.Event{}, "schema"
	}
	at, err := time.Parse(time.RFC3339, raw.Time)
	if err != nil {
		return domain.Event{}, "invalid"
	}
	seconds, err := strconv.ParseFloat(raw.Latency, 64)
	if err != nil {
		return domain.Event{}, "invalid"
	}
	event, err := domain.NewEvent(domain.Event{SiteID: raw.Site, RequestID: raw.Request, Route: raw.Route, Method: raw.Method, PathPattern: raw.Pattern, ConfigID: raw.Config, TargetID: raw.Target, UpstreamOutcome: raw.Outcome, RateRequest: raw.RateRequest, RateConnection: raw.RateConnection, Time: at, Status: raw.Status, Bytes: raw.Bytes}, seconds)
	if err != nil {
		return domain.Event{}, "invalid"
	}
	return event, ""
}
