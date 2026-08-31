package dfos

import "crypto/sha256"

// THE WORD FINGERPRINT — A KEY RENDERED FOR EYES, NEVER FOR BYTES.
//
// Byte-twin of dfos-protocol/src/key-proof/word-fingerprint.ts.
//
// KEY-PROOF.md's holder obligations put a human in the loop at exactly one point:
// a key travels between two surfaces — the holder's tool printing the key it
// presented, and the ceremony surface displaying the key that arrived — and the
// human is asked whether they match. This renders the thing that human compares.
// Six words, from the six leading bytes of SHA-256 over the key's multikey string,
// alternating the PGP even and odd tables (see pgp_word_list.go).
//
// WHY NOT SHOW THE MULTIKEY. A multikey is 48 base58 characters with no visual
// structure, and a human asked to compare two of them compares the first four and
// the last four. That check is defeated by a key whose ends happen to agree, and
// the effort of producing one is a vanity-key search, not a break. Six words carry
// 48 bits that a human actually reads all of, and the even/odd alternation means a
// transposed pair reads with the wrong syllable count rather than reading fine.
//
// WHY THE HASH AND NOT THE KEY'S OWN BYTES. Hashing spreads any structure the key
// material shares — every Ed25519 multikey starts z6Mk, so words taken from the
// key's leading bytes would open identically for every key in the protocol and
// the human would learn to skip them.
//
// THE MULTIKEY REMAINS THE IDENTIFIER. Nothing in the protocol matches, indexes,
// or verifies against a word fingerprint; the multikey string does all of that.
// A fingerprint is a display of a key, not a name for one, and two keys sharing a
// fingerprint is a 48-bit collision that costs a human a second look and costs the
// protocol nothing.
//
// TOTAL, AND DELIBERATELY UNVALIDATING. This hashes the string it is given, with
// no check that the string is a well-formed multikey, and it cannot fail. That is
// not laxity: the two surfaces being compared are trusted to have agreed on WHICH
// string they render — the multikey exactly as the chain declares it — and a
// surface that renders something else produces a fingerprint that visibly differs,
// which is the mismatch the comparison exists to surface. An error return here
// would only move that failure to a place the human never sees.

// fingerprintBytes is the number of digest bytes a fingerprint reads — six, for
// 48 bits and six words.
const fingerprintBytes = 6

// KeyWordFingerprint returns the word fingerprint of a key: six lowercase words,
// space-joined, from the first six bytes of SHA-256 over the UTF-8 bytes of the
// key's multikey string.
//
// Both surfaces a human compares a key across SHOULD render this, and render it
// from the same string — the publicKeyMultibase as the chain declares it, z… form,
// no did:key: prefix and no truncation.
//
// The input is not validated: this renders words for eyes, and admission of a
// multikey happens elsewhere.
//
//	KeyWordFingerprint("z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb")
//	// "ragtime decadence python coherence belfast provincial"
func KeyWordFingerprint(publicKeyMultibase string) string {
	digest := sha256.Sum256([]byte(publicKeyMultibase))
	return pgpWords(digest[:fingerprintBytes])
}
