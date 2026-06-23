import { describe, expect, it } from 'vitest';
import { dagCborCanonicalEncode } from '../src/crypto';

/*

  No Unicode normalization pin (PROTOCOL.md §"String Encoding")

  PROTOCOL.md mandates that string values commit to their EXACT UTF-8 byte
  sequence: implementations MUST NOT apply Unicode normalization (NFC/NFD/
  NFKC/NFKD) before dag-cbor encoding or signing. Two Unicode-equivalent but
  byte-distinct strings — e.g. a precomposed "é" (NFC, U+00E9) versus an "e"
  followed by a combining acute accent (NFD, U+0065 U+0301) — are DIFFERENT
  protocol values and MUST produce DIFFERENT CIDs. The reference encoder
  (dagCborCanonicalEncode) has no .normalize() step; this pin guards against
  one being introduced. CIDs are byte-pinned so a Go twin can match exactly.

*/

// Precomposed "é" — a single codepoint U+00E9 (NFC form).
const NFC = 'é';
// Decomposed "é" — "e" (U+0065) + combining acute accent (U+0301) (NFD form).
const NFD = 'é';

describe('dag-cbor no Unicode normalization (NFC vs NFD stay byte-distinct)', () => {
  it('the two forms are canonically inequivalent at the source level', () => {
    // sanity: they render the same but are NOT JS-equal — distinct byte sequences
    expect(NFC).not.toBe(NFD);
    expect(NFC.length).toBe(1);
    expect(NFD.length).toBe(2);
    expect(NFC.normalize('NFC')).toBe(NFD.normalize('NFC')); // equivalent under normalization
  });

  it('NFC vs NFD as an object value → different (pinned) CIDs', async () => {
    const nfc = await dagCborCanonicalEncode({ name: NFC });
    const nfd = await dagCborCanonicalEncode({ name: NFD });
    expect(nfc.cid.toString()).toBe('bafyreiffxn5cv3cscyo6hce46zza25xdrwj7esp3g4uchxnk3kk2j4fnzy');
    expect(nfd.cid.toString()).toBe('bafyreic2yxsivvkzvchuzp7qdppyyzjoltfl64izqu6j5mrumo6uwn4rfa');
    expect(nfc.cid.toString()).not.toBe(nfd.cid.toString());
  });

  it('NFC vs NFD as a bare string value → different (pinned) CIDs', async () => {
    const nfc = await dagCborCanonicalEncode(NFC);
    const nfd = await dagCborCanonicalEncode(NFD);
    expect(nfc.cid.toString()).toBe('bafyreidqdaj5nvnmtyeh4s2gtca32s7rc37okat2hn7kinwvcoynqbexg4');
    expect(nfd.cid.toString()).toBe('bafyreig27byz6rr2qammstdood666aowgwgkfawbbz4buuv6ler35kukri');
    expect(nfc.cid.toString()).not.toBe(nfd.cid.toString());
  });
});
