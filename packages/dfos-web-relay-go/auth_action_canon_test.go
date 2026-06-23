package relay

import (
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestMatchesResourceActionCanonicalization pins the relay's own copy of the
// action-coverage check (Relay.matchesResource) to the canonicalization
// documented in CREDENTIALS.md "Action Coverage": split on comma, trim,
// set-collapse, exact case-sensitive token equality, no action wildcard.
//
// matchesResource uses no relay state for action matching, so a zero-value
// Relay is sufficient.
func TestMatchesResourceActionCanonicalization(t *testing.T) {
	r := &Relay{}
	att := func(a string) []dfos.AttEntry {
		return []dfos.AttEntry{{Resource: "chain:c1", Action: a}}
	}

	if !r.matchesResource(att("read,write"), "chain:c1", "write") {
		t.Error("write should be covered by read,write")
	}
	if !r.matchesResource(att("write,read"), "chain:c1", "read") {
		t.Error("order-insensitive: read should be covered by write,read")
	}
	if !r.matchesResource(att(" read , write "), "chain:c1", "write") {
		t.Error("surrounding whitespace should be trimmed")
	}
	if !r.matchesResource(att("read,,write"), "chain:c1", "write") {
		t.Error("empty element should be dropped")
	}
	if r.matchesResource(att("Write"), "chain:c1", "write") {
		t.Error("action match must be case-sensitive (Write != write)")
	}
	if r.matchesResource(att("*"), "chain:c1", "write") {
		t.Error("there is no action wildcard ('*' is resource-only)")
	}
	if r.matchesResource(att("read,write"), "chain:c1", "delete") {
		t.Error("delete is not covered by read,write")
	}
}
