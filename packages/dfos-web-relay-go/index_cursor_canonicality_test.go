package relay

import (
	"strings"
	"testing"
)

// Both twins must agree on exactly which cursor strings are valid — a decoder
// that accepts non-canonical base64 (padding, whitespace) on one side is a
// live cross-implementation divergence the parity harness cannot see, because
// the harness only replays cursors the relays themselves emitted.

func nonCanonicalVariants(canonical string) []string {
	return []string{
		canonical + "=",
		canonical + "==",
		canonical + "\n",
		canonical + " ",
		" " + canonical,
	}
}

func TestOrderedCursorCanonicality(t *testing.T) {
	canonical := encodeIndexOrderedCursor("2026-08-25T00:00:00Z", "did:dfos:abc")
	cursor, ok := decodeIndexOrderedCursor(canonical)
	if !ok || cursor.Timestamp != "2026-08-25T00:00:00Z" || cursor.Key != "did:dfos:abc" {
		t.Fatalf("canonical ordered cursor did not decode: %v %v", cursor, ok)
	}
	for _, variant := range nonCanonicalVariants(canonical) {
		if _, ok := decodeIndexOrderedCursor(variant); ok {
			t.Fatalf("non-canonical ordered cursor accepted: %q", variant)
		}
	}
}

func TestCreditCursorCanonicality(t *testing.T) {
	contentID := strings.Repeat("a", 31)
	canonical := encodeIndexCreditCursor(contentID, 7)
	cursor, ok := decodeIndexCreditCursor(canonical)
	if !ok || cursor.ContentID != contentID || cursor.Position != 7 {
		t.Fatalf("canonical credit cursor did not decode: %v %v", cursor, ok)
	}
	for _, variant := range nonCanonicalVariants(canonical) {
		if _, ok := decodeIndexCreditCursor(variant); ok {
			t.Fatalf("non-canonical credit cursor accepted: %q", variant)
		}
	}
}
