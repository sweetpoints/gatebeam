package domain

import (
	"regexp"
	"strings"
	"time"
)

var objectKey = regexp.MustCompile(`^[0-9a-f-]{36}/[0-9]{4}-[0-9]{2}-[0-9]{2}/[0-9]{2}/[0-9a-f]{64}(-[0-9]{1,20}-[0-9]{1,20})?\.parquet$`)

var nodeObjectKey = regexp.MustCompile(`^[0-9a-f-]{36}/[0-9]{4}-[0-9]{2}-[0-9]{2}/[0-9]{2}/[0-9a-f-]{36}/[0-9a-f]{64}(-[0-9]{1,20}-[0-9]{1,20})?\.parquet$`)

const MaxScanBytes int64 = 2 << 30
const MaxQueryObjects = 4096
const MaxQueryRows = 10000

type Manifest struct {
	BatchID     string
	Objects     []Object
	CommittedAt time.Time
	Sequence    int64
}

func ValidObject(o Object) bool {
	validNamespace := o.SchemaVersion == 1 && (o.NodeID == "" || ValidSite(o.NodeID)) && objectKey.MatchString(o.Key) || o.SchemaVersion == 2 && ValidSite(o.NodeID) && nodeObjectKey.MatchString(o.Key) && strings.HasPrefix(o.Key, o.SiteID+"/"+o.Hour+"/"+o.NodeID+"/")
	return validNamespace && ValidSite(o.SiteID) && strings.HasPrefix(o.Key, o.SiteID+"/"+o.Hour+"/") && len(o.Checksum) == 64 && strings.Trim(o.Checksum, "0123456789abcdef") == "" && o.Rows > 0 && o.Bytes > 0 && o.Bytes <= MaxScanBytes && !o.MinTime.After(o.MaxTime)
}
func ValidateObjects(f QueryFilter, objects []Object) error {
	if e := f.Validate(); e != nil {
		return e
	}
	if len(objects) > MaxQueryObjects {
		return ErrCapacity
	}
	sites := map[string]bool{}
	for _, s := range f.SiteIDs {
		sites[s] = true
	}
	var total int64
	seen := map[string]bool{}
	for _, o := range objects {
		if !ValidObject(o) || seen[o.Key] || !sites[o.SiteID] || o.MinTime.Compare(f.To) >= 0 || o.MaxTime.Before(f.From) {
			return ErrInvalid
		}
		seen[o.Key] = true
		total += o.Bytes
		if total > MaxScanBytes {
			return ErrCapacity
		}
	}
	return nil
}
