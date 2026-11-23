package domain

import (
	"strings"
	"testing"
	"time"
)

func TestHistoryManifestBoundsAndWhitelist(t *testing.T) {
	now := time.Now()
	f := QueryFilter{SiteIDs: []string{"00000000-0000-0000-0000-000000000001"}, From: now, To: now.Add(time.Hour)}
	if e := f.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"';SELECT 1;--", "s3://bucket/x", "/rawpath"} {
		bad := f
		bad.Route = v
		if bad.Validate() == nil {
			t.Fatal("unsafe route", v)
		}
	}
	o := Object{SchemaVersion: 1, SiteID: f.SiteIDs[0], Hour: "2026-11-07/12", Key: f.SiteIDs[0] + "/2026-11-07/12/" + strings.Repeat("a", 64) + ".parquet", Checksum: strings.Repeat("b", 64), Rows: 1, Bytes: MaxScanBytes, MinTime: now, MaxTime: now}
	if e := ValidateObjects(f, []Object{o}); e != nil {
		t.Fatal(e)
	}
	o.Bytes++
	if ValidateObjects(f, []Object{o}) == nil {
		t.Fatal("scan limit bypass")
	}
	o.Bytes = 1
	o.Key = "s3://other/x"
	if ValidateObjects(f, []Object{o}) == nil {
		t.Fatal("URI accepted")
	}
}
