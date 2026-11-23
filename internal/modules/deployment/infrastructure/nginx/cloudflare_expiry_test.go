package nginx

import (
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestCloudflareNativeExpiryRange(t *testing.T) {
	for _, cutoff := range []int64{1, 10, 100, 1001, 1780000000, 9999999999} {
		pattern, e := cloudflareExpiryPattern(time.Unix(cutoff, 0))
		if e != nil {
			t.Fatal(e)
		}
		re, e := regexp.Compile(pattern)
		if e != nil {
			t.Fatal(e)
		}
		for _, n := range []int64{0, 1, 9, 10, 99, 100, 999, cutoff - 1, cutoff, cutoff + 1, 99999999999} {
			want := n >= 0 && n < cutoff
			if re.MatchString(strconv.FormatInt(n, 10)+".999") != want {
				t.Fatalf("cutoff %d value %d", cutoff, n)
			}
		}
		for _, bad := range []string{"-1.000", "00.000", "1", "1.0", "1.0000", "NaN", "Inf", "1780000000.123\n", "9999999999999999999999.000"} {
			if re.MatchString(bad) {
				t.Fatal("malformed native time accepted", bad)
			}
		}
	}
	if _, e := cloudflareExpiryPattern(time.Unix(-1, 0)); e == nil {
		t.Fatal("negative expiry")
	}
	if _, e := cloudflareExpiryPattern(time.Unix(10000000000, 0)); e == nil {
		t.Fatal("overflow expiry")
	}
}
