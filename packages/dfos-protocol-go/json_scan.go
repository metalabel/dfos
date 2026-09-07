package dfos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// AssertCanonicalJSONText rejects a signed JSON document whose raw text carries
// something its decoded value can no longer show:
//
//  1. DUPLICATE KEYS — PROTOCOL: "A payload containing duplicate keys is
//     malformed: the signature commits to the raw payload bytes while the CID
//     derives from the decoded value." encoding/json resolves a duplicate
//     silently (last wins), so the only place to see one is the text.
//  2. LONE SURROGATE ESCAPES — a \uD800-class escape with no pair. encoding/json
//     replaces it with U+FFFD while the TypeScript reference keeps it, so the
//     two would derive different CIDs from the same signed bytes. Refusing the
//     escape is the one verdict both can reach.
//  3. INVALID UTF-8 — raw bytes encoding/json would likewise replace.
//
// This is a tokenizer, not a parser: it does not validate the grammar —
// json.Unmarshal is the grammar judge, and this walk stops at the first thing it
// cannot read. It tracks only enough structure to know which strings are member
// names of which object.
//
// MUST match the TS reference (assertCanonicalJsonText in crypto/json-scan.ts).
func AssertCanonicalJSONText(text []byte) error {
	if !utf8.Valid(text) {
		return fmt.Errorf("json text is not valid UTF-8")
	}

	// one frame per open container; awaitingKey is true in an object frame
	// exactly where a member name may start (right after '{', and after a ',')
	type frame struct {
		isObject    bool
		keys        map[string]bool
		awaitingKey bool
	}
	var frames []*frame

	for i := 0; i < len(text); {
		switch c := text[i]; c {
		case '"':
			end := scanJSONStringToken(text, i)
			if end < 0 {
				return nil // unterminated — let json.Unmarshal render the verdict
			}
			raw := text[i:end]
			escaped := bytes.IndexByte(raw, '\\') >= 0
			if escaped && hasLoneSurrogateEscape(raw) {
				return fmt.Errorf("string with an unpaired surrogate is not canonicalizable")
			}
			value, ok := decodeJSONStringToken(raw, escaped)
			if !ok {
				return nil
			}
			if n := len(frames); n > 0 {
				top := frames[n-1]
				if top.isObject && top.awaitingKey {
					if top.keys[value] {
						return fmt.Errorf("duplicate JSON key is malformed: %q", value)
					}
					top.keys[value] = true
					top.awaitingKey = false
				}
			}
			i = end
			continue
		case '{':
			frames = append(frames, &frame{isObject: true, keys: map[string]bool{}, awaitingKey: true})
		case '[':
			frames = append(frames, &frame{})
		case '}', ']':
			if n := len(frames); n > 0 {
				frames = frames[:n-1]
			}
		case ',':
			if n := len(frames); n > 0 && frames[n-1].isObject {
				frames[n-1].awaitingKey = true
			}
		}
		i++
	}
	return nil
}

// scanJSONStringToken returns the index just past the closing quote of the
// string token starting at start, or -1 when the token is unterminated.
func scanJSONStringToken(text []byte, start int) int {
	for i := start + 1; i < len(text); {
		switch text[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		default:
			i++
		}
	}
	return -1
}

// decodeJSONStringToken returns the string a raw "…" token denotes.
func decodeJSONStringToken(raw []byte, escaped bool) (string, bool) {
	if !escaped {
		return string(raw[1 : len(raw)-1]), true
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// hasLoneSurrogateEscape reports whether the raw string token carries a \uXXXX
// escape in the surrogate range that is not part of a well-formed pair. It reads
// the escapes rather than the decoded string because encoding/json has already
// replaced them with U+FFFD by then — the defect is invisible after the decode.
func hasLoneSurrogateEscape(raw []byte) bool {
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != 'u' {
			i += 2
			continue
		}
		first, ok := parseHex4(raw, i+2)
		if !ok {
			i += 2
			continue
		}
		if utf16.IsSurrogate(rune(first)) {
			second, ok := parseHex4(raw, i+8)
			if i+6 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' || !ok {
				return true
			}
			if utf16.DecodeRune(rune(first), rune(second)) == utf8.RuneError {
				return true
			}
			i += 12
			continue
		}
		i += 6
	}
	return false
}

// parseHex4 reads the four hex digits at offset as a uint16.
func parseHex4(raw []byte, offset int) (uint16, bool) {
	if offset+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, c := range raw[offset : offset+4] {
		var digit uint16
		switch {
		case c >= '0' && c <= '9':
			digit = uint16(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = uint16(c-'A') + 10
		default:
			return 0, false
		}
		value = value<<4 | digit
	}
	return value, true
}
