// Package domain owns bounded, sanitized observations and mergeable statistics.
package domain

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid observation")
var ErrIncomplete = errors.New("log prefix incomplete")
var ErrSourceChanged = errors.New("log source changed")
var ErrCapacity = errors.New("observability capacity exceeded")
var ErrDenied = errors.New("statistics permission denied")

const MaxRows = 1024
const MaxRead = 1 << 20
const MaxLine = 16 << 10

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var requestID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func ValidSite(id string) bool { return uuid.MatchString(id) }
func ValidRoute(v string) bool {
	if v == "default" || v == "-1" {
		return true
	}
	n, e := strconv.Atoi(v)
	return e == nil && n >= 0 && n < 1000 && strconv.Itoa(n) == v
}
func ValidMethod(v string) bool {
	switch v {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE", "OTHER":
		return true
	}
	return false
}

// Event is the entire persistence allowlist. Free paths, headers and peer data
// deliberately have no destination field, even when a legacy producer sends them.
type Event struct {
	NodeID                                           string
	SiteID, RequestID, Route, Method                 string
	PathPattern, ConfigID, TargetID, UpstreamOutcome string
	RateRequest, RateConnection                      string
	Time                                             time.Time
	Status                                           int
	Bytes                                            int64
	Micros                                           int64
}

// NewEvent applies observation policy to already-decoded values. Numeric
// duration bounds and canonical dimensions belong here; no producer encoding
// or wire timestamp format is part of this contract.
func NewEvent(event Event, latencySeconds float64) (Event, error) {
	if math.IsNaN(latencySeconds) || math.IsInf(latencySeconds, 0) || latencySeconds < 0 || latencySeconds > 86400 {
		return Event{}, ErrInvalid
	}
	if event.Time.Year() < 2020 || event.Time.Year() > 2100 || !ValidSite(event.SiteID) || !requestID.MatchString(event.RequestID) || !ValidRoute(event.Route) || event.Status < 100 || event.Status > 599 || event.Bytes < 0 || event.Bytes > 1<<50 {
		return Event{}, ErrInvalid
	}
	if len(event.PathPattern) > 2048 || strings.ContainsAny(event.PathPattern, "?\n\r\t\x00") || event.PathPattern != "" && !strings.HasPrefix(event.PathPattern, "/") || event.ConfigID != "" && (len(event.ConfigID) != 64 || strings.Trim(event.ConfigID, "0123456789abcdef") != "") || event.TargetID != "" && !ValidSite(event.TargetID) {
		return Event{}, ErrInvalid
	}
	switch event.UpstreamOutcome {
	case "", "none", "success", "redirect", "client_error", "server_error", "error":
	default:
		return Event{}, ErrInvalid
	}
	for _, v := range []string{event.RateRequest, event.RateConnection} {
		switch v {
		case "", "PASSED", "DELAYED", "REJECTED", "DELAYED_DRY_RUN", "REJECTED_DRY_RUN":
		default:
			return Event{}, ErrInvalid
		}
	}
	if !ValidMethod(event.Method) {
		event.Method = "OTHER"
	}
	event.Time = event.Time.UTC()
	event.Micros = int64(math.Round(latencySeconds * 1e6))
	return event, nil
}
