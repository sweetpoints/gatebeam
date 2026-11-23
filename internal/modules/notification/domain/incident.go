// Package domain owns ordered alert transitions and safe notification content.
package domain

import (
	"errors"
	"fmt"
)

var ErrInvalid = errors.New("invalid notification request")
var ErrDenied = errors.New("notification access denied")
var ErrNotFound = errors.New("notification not found")
var ErrConflict = errors.New("notification revision conflict")
var ErrDelivery = errors.New("notification provider unavailable")

type Event struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	ResourceID  string `json:"resource_id"`
	Fingerprint string `json:"fingerprint"`
	Version     int64  `json:"version"`
	State       string `json:"state"`
	Message     string `json:"-"` // Compatibility input; deliberately never persisted or rendered.
	LagSeconds  int64  `json:"lag_seconds"`
}

var labels = map[string]string{"target_health": "target health", "target_dns": "target DNS", "certificate_renewal": "certificate renewal", "certificate_expiry": "certificate expiry", "log_records": "log records rejected", "ingestion_lag": "ingestion lag", "log_pipeline": "log pipeline", "archive_pipeline": "archive pipeline", "query_pipeline": "query pipeline", "channel_test": "channel test"}

func (e Event) Validate() error {
	if labels[e.Kind] == "" || e.ID == "" || len(e.ID) > 256 || e.ResourceID == "" || len(e.ResourceID) > 256 || e.Fingerprint == "" || len(e.Fingerprint) > 128 || e.Version < 1 || e.LagSeconds < 0 || (e.State != "firing" && e.State != "resolved") {
		return ErrInvalid
	}
	return nil
}
func (e Event) Render() string {
	text := "Gatebeam: " + labels[e.Kind] + " " + e.State
	// Resource identity is only returned inside an authorized API view; external
	// messages deliberately contain no caller-provided names, URLs, or errors.
	if e.Kind == "ingestion_lag" {
		text += fmt.Sprintf("; ingestion lag %d seconds", e.LagSeconds)
	}
	return text
}

type Incident struct {
	Version int64
	State   string
}

func (i *Incident) Observe(version int64, state string) bool {
	if version <= i.Version {
		return false
	}
	changed := i.State != state && (i.State != "" || state == "firing")
	i.Version = version
	i.State = state
	return changed
}
