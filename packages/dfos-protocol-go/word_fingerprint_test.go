package dfos

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// THE WORD FINGERPRINT — the tables, the encoding, and the twin pin.
//
// Byte-twin of dfos-protocol/tests/word-fingerprint.spec.ts, case for case.
//
// The risk this file is built around is not the algorithm — six bytes of SHA-256
// through two lookup tables has nowhere to hide a bug. It is the TABLES: 512
// hand-transcribable words where a single wrong entry produces a fingerprint that
// looks perfectly plausible, renders identically on the surface that got the same
// bad table, and silently fails to render identically anywhere else. Three
// independent checks pin them:
//
//  1. THE PUBLISHED EXAMPLE. The PGP documentation's own worked example — a
//     20-byte fingerprint and the exact 20 words it renders as — exercises 20
//     positions across both tables against a value nobody here chose.
//
//  2. THE SHAPE. 256 entries per table, no duplicates within a table, none shared
//     across tables, all lowercase. A dropped or doubled entry shifts every word
//     after it, and this catches that even where no vector reaches.
//
//  3. THE TWIN CHECKSUM. wordListChecksum is SHA-256 over the newline-joined
//     concatenation of both tables, and the same constant is pinned in the TS
//     suite. One divergent word in either language — one letter — turns both
//     suites red, so the tables cannot drift apart silently.
//
// Check 3 is the one that matters most: checks 1 and 2 can both pass on two
// DIFFERENT tables, because 20 words and a shape do not cover 512 entries.

// -----------------------------------------------------------------------------
// vectors — every literal below is pinned identically in word-fingerprint.spec.ts
// -----------------------------------------------------------------------------

// wordListChecksum is SHA-256 over the newline-joined concatenation of the even
// table then the odd table. The cross-language pin: this constant appears
// verbatim in the TS suite.
const wordListChecksum = "41db18a831d9c40dc35b374ef36f0bf616d4f563768fcc1a5aa11c7b6530cf5e"

// The worked example from the PGP word list's own documentation.
const publishedExampleHex = "e58294f2e9a227486e8b061b31cc528fd7fa3f19"
const publishedExampleWords = "topmost istanbul pluto vagabond treadmill pacific brackish dictator " +
	"goldfish medusa afflict bravado chatter revolver dupont midsummer " +
	"stopwatch whimsical cowbell bottomless"

// The two reference keys from specs/PROTOCOL.md, and their fingerprints.
const (
	referenceKeyA            = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
	referenceKeyAFingerprint = "ragtime decadence python coherence belfast provincial"
	referenceKeyB            = "z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK"
	referenceKeyBFingerprint = "talon hurricane breadline retrieval island hazardous"
)

var sixLowercaseWords = regexp.MustCompile(`^[a-z]+( [a-z]+){5}$`)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// -----------------------------------------------------------------------------
// the tables
// -----------------------------------------------------------------------------

func TestWordTablesHoldNoDuplicatesWithinATable(t *testing.T) {
	for _, table := range []struct {
		name  string
		words [256]string
	}{{"even", pgpEvenWords}, {"odd", pgpOddWords}} {
		seen := make(map[string]int, 256)
		for i, word := range table.words {
			if prior, dup := seen[word]; dup {
				t.Errorf("%s table: %q appears at both %d and %d", table.name, word, prior, i)
			}
			seen[word] = i
		}
	}
}

func TestWordTablesShareNoWordAcrossTables(t *testing.T) {
	even := make(map[string]bool, 256)
	for _, word := range pgpEvenWords {
		even[word] = true
	}
	for i, word := range pgpOddWords {
		if even[word] {
			t.Errorf("odd table entry %d (%q) also appears in the even table", i, word)
		}
	}
}

func TestWordTablesAreEntirelyLowercaseASCIILetters(t *testing.T) {
	lettersOnly := regexp.MustCompile(`^[a-z]+$`)
	for i, word := range pgpEvenWords {
		if !lettersOnly.MatchString(word) {
			t.Errorf("even table entry %d is %q", i, word)
		}
	}
	for i, word := range pgpOddWords {
		if !lettersOnly.MatchString(word) {
			t.Errorf("odd table entry %d is %q", i, word)
		}
	}
}

// The even table is the two-syllable list, the odd table the three-syllable one;
// the documented maximum word lengths are 9 and 11 respectively.
func TestWordTablesSeparateBySyllableCount(t *testing.T) {
	longest := func(words [256]string) int {
		longestLen := 0
		for _, word := range words {
			if len(word) > longestLen {
				longestLen = len(word)
			}
		}
		return longestLen
	}
	if got := longest(pgpEvenWords); got != 9 {
		t.Errorf("longest even word is %d letters, want 9", got)
	}
	if got := longest(pgpOddWords); got != 11 {
		t.Errorf("longest odd word is %d letters, want 11", got)
	}
}

func TestWordTablesHashToTheChecksumTheTypeScriptSuitePins(t *testing.T) {
	all := make([]string, 0, 512)
	all = append(all, pgpEvenWords[:]...)
	all = append(all, pgpOddWords[:]...)
	joined := strings.Join(all, "\n")
	digest := sha256.Sum256([]byte(joined))
	if got := hex.EncodeToString(digest[:]); got != wordListChecksum {
		t.Errorf("word list checksum = %s, want %s", got, wordListChecksum)
	}
}

// -----------------------------------------------------------------------------
// the encoding
// -----------------------------------------------------------------------------

func TestPGPWordsRendersThePublishedExampleExactly(t *testing.T) {
	if got := pgpWords(mustHex(t, publishedExampleHex)); got != publishedExampleWords {
		t.Errorf("pgpWords(published example) =\n  %s\nwant\n  %s", got, publishedExampleWords)
	}
}

// The documentation's own illustration: "E582" is topmost istanbul, while the
// same two bytes swapped are two different words entirely.
func TestPGPWordsAlternatesTablesByOffset(t *testing.T) {
	if got := pgpWords(mustHex(t, "e582")); got != "topmost istanbul" {
		t.Errorf(`pgpWords(e582) = %q, want "topmost istanbul"`, got)
	}
	if got := pgpWords(mustHex(t, "82e5")); got != "miser travesty" {
		t.Errorf(`pgpWords(82e5) = %q, want "miser travesty"`, got)
	}
}

func TestPGPWordsRendersByteZeroFromWhicheverTableTheOffsetSelects(t *testing.T) {
	want := pgpEvenWords[0] + " " + pgpOddWords[0]
	if got := pgpWords(mustHex(t, "0000")); got != want {
		t.Errorf("pgpWords(0000) = %q, want %q", got, want)
	}
	if pgpEvenWords[0] == pgpOddWords[0] {
		t.Errorf("byte 0 renders identically in both tables (%q)", pgpEvenWords[0])
	}
}

func TestPGPWordsRendersEmptyOctetsAsTheEmptyString(t *testing.T) {
	if got := pgpWords(nil); got != "" {
		t.Errorf("pgpWords(nil) = %q, want empty", got)
	}
	if got := pgpWords([]byte{}); got != "" {
		t.Errorf("pgpWords(empty) = %q, want empty", got)
	}
}

// -----------------------------------------------------------------------------
// the fingerprint
// -----------------------------------------------------------------------------

func TestKeyWordFingerprintRendersTheReferenceKeys(t *testing.T) {
	for _, tc := range []struct{ key, want string }{
		{referenceKeyA, referenceKeyAFingerprint},
		{referenceKeyB, referenceKeyBFingerprint},
	} {
		if got := KeyWordFingerprint(tc.key); got != tc.want {
			t.Errorf("KeyWordFingerprint(%s) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestKeyWordFingerprintDistinguishesTheTwoReferenceKeys(t *testing.T) {
	if KeyWordFingerprint(referenceKeyA) == KeyWordFingerprint(referenceKeyB) {
		t.Error("the two reference keys share a fingerprint")
	}
}

func TestKeyWordFingerprintIsSixLowercaseWordsJoinedBySingleSpaces(t *testing.T) {
	for _, key := range []string{referenceKeyA, referenceKeyB} {
		got := KeyWordFingerprint(key)
		if !sixLowercaseWords.MatchString(got) {
			t.Errorf("KeyWordFingerprint(%s) = %q, want six lowercase words", key, got)
		}
		if n := len(strings.Split(got, " ")); n != 6 {
			t.Errorf("KeyWordFingerprint(%s) has %d words, want 6", key, n)
		}
	}
}

func TestKeyWordFingerprintIsDeterministicAcrossCalls(t *testing.T) {
	if KeyWordFingerprint(referenceKeyA) != KeyWordFingerprint(referenceKeyA) {
		t.Error("KeyWordFingerprint is not deterministic")
	}
}

func TestKeyWordFingerprintIsTheSixLeadingDigestBytesAndNothingElse(t *testing.T) {
	digest := sha256.Sum256([]byte(referenceKeyA))
	if got, want := KeyWordFingerprint(referenceKeyA), pgpWords(digest[:6]); got != want {
		t.Errorf("KeyWordFingerprint = %q, want %q", got, want)
	}
}

// The obligation is that both surfaces render the SAME string — the z… form as
// the chain declares it. Anything else is a different fingerprint, which is
// exactly the mismatch a human comparison is there to catch.
func TestKeyWordFingerprintHashesTheMultikeyString(t *testing.T) {
	if KeyWordFingerprint("did:key:"+referenceKeyA) == referenceKeyAFingerprint {
		t.Error("a did:key: prefixed form produced the bare multikey's fingerprint")
	}
	if KeyWordFingerprint(referenceKeyA[:20]) == referenceKeyAFingerprint {
		t.Error("a truncated form produced the full multikey's fingerprint")
	}
}

// Total by construction: the function has no failure mode to surface to a caller
// that is mid-render.
func TestKeyWordFingerprintRendersTheEmptyStringRatherThanFailing(t *testing.T) {
	if got := KeyWordFingerprint(""); !sixLowercaseWords.MatchString(got) {
		t.Errorf(`KeyWordFingerprint("") = %q, want six lowercase words`, got)
	}
}
