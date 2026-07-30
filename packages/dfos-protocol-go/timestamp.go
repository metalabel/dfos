package dfos

import (
	"sync"
	"time"
)

// protocolTimeFormat is the canonical timestamp format for DFOS operations.
const protocolTimeFormat = "2006-01-02T15:04:05.000Z"

// ParseProtocolTimestamp parses a canonical DFOS operation timestamp: fixed
// 3-digit fraction, literal Z, full calendar validation. Deliberately stricter
// than RFC 3339 (no numeric offsets, no variable fraction) so two
// implementations cannot disagree about whether a signed timestamp is
// well-formed.
//
// This is the ONE parse every consumer of a signed timestamp should use when it
// needs a comparable instant — RFC3339/RFC3339Nano accept inputs the protocol
// rejects, which is how two verifiers end up ordering the same two signed
// timestamps differently. TS twin: parseProtocolTimestampUnix. The 22-case
// vector set asserting the two grammars agree verdict-for-verdict lives in
// timestamp_grammar_test.go and dfos-protocol/tests/timestamp-grammar.spec.ts.
func ParseProtocolTimestamp(value string) (time.Time, error) {
	return time.Parse(protocolTimeFormat, value)
}

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
