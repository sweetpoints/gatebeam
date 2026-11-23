package nginx

import (
	"strconv"
	"strings"
	"time"
)

// cloudflareExpiryPattern permits only canonical native $msec values strictly
// before the conservatively rounded expiry second. At most one range per digit
// is emitted: no untrusted regex, unbounded enumeration or floating-point time.
func cloudflareExpiryPattern(expiry time.Time) (string, error) {
	cutoff := expiry.Unix()
	if cutoff < 1 || cutoff > 9999999999 {
		return "", ErrInvalid
	}
	digits := strconv.FormatInt(cutoff, 10)
	parts := []string{"0"}
	if len(digits) > 1 {
		parts = append(parts, "[1-9][0-9]{0,"+strconv.Itoa(len(digits)-2)+"}")
	}
	for i, digit := range digits {
		low := byte('0')
		if i == 0 {
			low = '1'
		}
		high := byte(digit) - 1
		if high < low {
			continue
		}
		term := digits[:i]
		if low == high {
			term += string(low)
		} else {
			term += "[" + string(low) + "-" + string(high) + "]"
		}
		if remaining := len(digits) - i - 1; remaining > 0 {
			term += "[0-9]{" + strconv.Itoa(remaining) + "}"
		}
		parts = append(parts, term)
	}
	return "^(?:" + strings.Join(parts, "|") + ")\\.[0-9]{3}\\z", nil
}
