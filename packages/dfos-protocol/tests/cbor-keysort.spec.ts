import { describe, expect, it } from 'vitest';
import { dagCborCanonicalEncode } from '../src/crypto';

/*

  WP-5 — dag-cbor equal-length key sort pin (TS twin)

  Both encoders sort map keys length-first then byte-wise (TS @ipld/dag-cbor's
  cborg compareBytes; Go cbor.CoreDetEncOptions SortBytewiseLexical). The keys
  in each object below are EQUAL byte-length and differ only by a multi-byte
  UTF-8 codepoint — the case that separates a byte-wise sort from a
  codepoint/collation sort. The expected CIDs are byte-identical to the Go twin
  (dfos-protocol-go/cbor_keysort_test.go). Keep the two pins in lockstep.

*/

describe('dag-cbor multibyte-key sort pin (Go twin parity)', () => {
  it('equal-length keys differing by a 2-byte codepoint → pinned CID', async () => {
    // "aé" and "azz" are both 3 bytes in UTF-8 (é = 2 bytes)
    const enc = await dagCborCanonicalEncode({ aé: 1, azz: 2 } as unknown as Record<
      string,
      unknown
    >);
    expect(enc.cid.toString()).toBe('bafyreihtzmqnfk5pk63tew7x2h525ntozjlduzhasiadw6fes4iqcfxcqe');
  });

  it('equal-length keys differing by a 3-byte codepoint → pinned CID', async () => {
    // "日a" and "azzz" are both 4 bytes in UTF-8 (日 = 3 bytes)
    const enc = await dagCborCanonicalEncode({ 日a: 1, azzz: 2 } as unknown as Record<
      string,
      unknown
    >);
    expect(enc.cid.toString()).toBe('bafyreih2na7yfz3rrvk3jrhktnb3ayr7gxtnqyqf742kb6iz3va7efwvui');
  });
});
