package logfile

import (
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"strings"
	"testing"
)

func TestWhitelistAndSchema(t *testing.T) {
	line := `{"schema_version":1,"site_id":"11111111-1111-4111-8111-111111111111","request_id":"0123456789abcdef0123456789abcdef","time":"2026-11-07T00:00:00Z","route":"0","method":"GET","status":200,"bytes_sent":20,"request_time":"0.012","path":"/secret?token=SECRET","cookie":"SECRET","authorization":"Bearer SECRET","body":"4111111111111111","signature":"SECRET","query":"token=SECRET"}`
	e, reason := decode([]byte(line))
	if reason != "" || e.Micros != 12000 || e.Route != "0" {
		t.Fatalf("valid whitelist observation rejected: %+v %s", e, reason)
	}
	if strings.Contains(fmt.Sprint(e), "SECRET") || strings.Contains(fmt.Sprint(e), "4111111111111111") {
		t.Fatal("unlisted wire fields escaped into typed event")
	}
	longPattern := strings.Repeat("a", 2047)
	extended := strings.TrimSuffix(line, "}") + `,"path_pattern":"/` + longPattern + `"}`
	if _, reason := decode([]byte(extended)); reason != "" {
		t.Fatal("valid maximum configured path rejected", reason)
	}
	for _, p := range []struct{ old, new string }{{`"schema_version":1`, `"schema_version":2`}, {`"route":"0"`, `"route":"secret"`}, {`"request_time":"0.012"`, `"request_time":"NaN"`}} {
		if _, r := decode([]byte(strings.Replace(line, p.old, p.new, 1))); r == "" {
			t.Fatal("unsafe observation accepted")
		}
	}
}

func TestWireDecodeRejectsSchemaAndMalformedFieldsWithoutPayload(t *testing.T) {
	line := `{"schema_version":1,"site_id":"11111111-1111-4111-8111-111111111111","request_id":"0123456789abcdef0123456789abcdef","time":"2026-11-07T00:00:00Z","route":"0","method":"GET","status":200,"bytes_sent":20,"request_time":"0.012"}`
	cases := []struct{ line, reason string }{{strings.Replace(line, `"schema_version":1`, `"schema_version":9`, 1), "schema"}, {`{"schema_version":1,"body":"SECRET"`, "invalid"}, {strings.Replace(line, `2026-11-07T00:00:00Z`, `SECRET`, 1), "invalid"}, {strings.Replace(line, `"0.012"`, `"Infinity"`, 1), "invalid"}, {strings.Replace(line, `"0.012"`, `"secret"`, 1), "invalid"}, {strings.Repeat("X", domain.MaxLine+1), "invalid"}}
	for _, c := range cases {
		event, reason := decode([]byte(c.line))
		if reason != c.reason || event != (domain.Event{}) {
			t.Fatalf("unsafe decoder result: reason=%s", reason)
		}
	}
	event, reason := decode([]byte(strings.Replace(line, `"GET"`, `"SECRET"`, 1)))
	if reason != "" || event.Method != "OTHER" {
		t.Fatal("unknown method not sanitized", reason)
	}
}
