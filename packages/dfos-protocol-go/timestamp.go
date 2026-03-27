package dfos

import (
	"sync"
	"time"
)

// protocolTimeFormat is the canonical timestamp format for DFOS operations.
const protocolTimeFormat = "2006-01-02T15:04:05.000Z"

// protocolTimestamp returns a UTC timestamp suitable for DFOS operations,
// guaranteed to be strictly monotonically increasing at millisecond precision.
// This prevents timestamp collisions when signing operations in rapid succession.
var protocolTimestamp = func() func() time.Time {
	var mu sync.Mutex
	var last int64

	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now().UTC().Truncate(time.Millisecond)
		ms := now.UnixMilli()
		if ms <= last {
			ms = last + 1
			now = time.UnixMilli(ms).UTC()
		}
		last = ms
		return now
	}
}()
