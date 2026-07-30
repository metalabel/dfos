package dfos

import (
	"testing"
	"time"
)

// timestampGrammarVectors pins the strict createdAt grammar. The same 22 cases
// are asserted in the TS twin (dfos-protocol/tests/timestamp-grammar.spec.ts)
// with byte-identical accept/reject verdicts: the strict gate is Go
// time.Parse("2006-01-02T15:04:05.000Z") vs TS
// z.iso.datetime({offset:false, precision:3}) — NOT RFC3339Nano. Both require a
// fixed 3-digit fraction and a literal Z, and both perform full calendar
// validation (real month/day, leap-second reject, leap-year aware).
var timestampGrammarVectors = []struct {
	input string
	valid bool
}{
	{"2026-03-07T00:00:00.000Z", true},       // canonical
	{"2026-03-07T00:00:00Z", false},          // no fraction
	{"2026-03-07T00:00:00.00Z", false},       // 2-digit fraction
	{"2026-03-07T00:00:00.0000Z", false},     // 4-digit fraction
	{"2026-03-07T00:00:00.000+00:00", false}, // numeric offset
	{"2026-03-07T00:00:00.000", false},       // missing Z
	{"2026-03-07T00:00:00.000z", false},      // lowercase z
	{"2026-13-07T00:00:00.000Z", false},      // month 13
	{"2026-02-30T00:00:00.000Z", false},      // Feb 30
	{"2026-03-07T24:00:00.000Z", false},      // hour 24
	{"2026-03-07T00:60:00.000Z", false},      // minute 60
	{"2026-03-07T00:00:60.000Z", false},      // second 60 (non leap-second)
	{"2026-03-07T00:00:00.000 Z", false},     // space before Z
	{"2026-3-7T00:00:00.000Z", false},        // non-zero-padded
	{"0000-01-01T00:00:00.000Z", true},       // year 0
	{"9999-12-31T23:59:59.999Z", true},       // year 9999
	{"2024-02-29T00:00:00.000Z", true},       // valid leap day
	{"2023-02-29T00:00:00.000Z", false},      // invalid leap day
	{"2026-03-07T00:00:00.000Z ", false},     // trailing space
	{" 2026-03-07T00:00:00.000Z", false},     // leading space
	{"2026-03-07 00:00:00.000Z", false},      // space instead of T
	{"2026-03-07T23:59:60.000Z", false},      // leap second
}

// TestTimestampGrammarParity asserts the Go strict createdAt grammar matches the
// TS twin verdict-for-verdict across the 22-case vector set.
func TestTimestampGrammarParity(t *testing.T) {
	for _, v := range timestampGrammarVectors {
		_, err := time.Parse(protocolTimeFormat, v.input)
		got := err == nil
		if got != v.valid {
			t.Errorf("grammar mismatch for %q: got valid=%v, want %v", v.input, got, v.valid)
		}
	}
}

// TestParseProtocolTimestampMatchesGrammar asserts the exported parse accepts
// exactly the canonical grammar — anything it rejects has no comparable instant, so
// consumers must not derive a boundary from it.
func TestParseProtocolTimestampMatchesGrammar(t *testing.T) {
	for _, v := range timestampGrammarVectors {
		_, err := ParseProtocolTimestamp(v.input)
		if (err == nil) != v.valid {
			t.Errorf("ParseProtocolTimestamp(%q): valid=%v, want %v", v.input, err == nil, v.valid)
		}
	}
}

// TestParseProtocolTimestampUnixSeconds pins the seconds conversion (floor, never
// round) that the credential temporal basis depends on.
func TestParseProtocolTimestampUnixSeconds(t *testing.T) {
	epoch, err := ParseProtocolTimestamp("1970-01-01T00:00:00.000Z")
	if err != nil || epoch.Unix() != 0 {
		t.Fatalf("epoch: %v (unix %d)", err, epoch.Unix())
	}
	sub, err := ParseProtocolTimestamp("1970-01-01T00:00:00.999Z")
	if err != nil || sub.Unix() != 0 {
		t.Fatalf("sub-second must floor to 0: %v (unix %d)", err, sub.Unix())
	}
	whole, err := ParseProtocolTimestamp("2026-03-07T00:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	frac, err := ParseProtocolTimestamp("2026-03-07T00:00:00.999Z")
	if err != nil {
		t.Fatal(err)
	}
	if whole.Unix() != frac.Unix() {
		t.Fatalf("millisecond remainder must floor away: %d vs %d", whole.Unix(), frac.Unix())
	}
}
