import { describe, expect, it } from 'vitest';
import { dagCborCanonicalEncode } from '../src/crypto';

/*

  Canonical-encode guards

  `dagCborCanonicalEncode` is the one place every CID in the protocol comes
  from, so it is the one place a value that two implementations would encode
  differently has to be refused. Two such values exist beyond the number policy
  (pinned in cbor-no-unicode-normalization.spec.ts and the WP-0 vectors):

  1. A LONE SURROGATE. `JSON.stringify` keeps it as a `\uD800` escape, but the
     CBOR string encoder normalizes it to U+FFFD — so a payload carrying one and
     a payload carrying a literal U+FFFD would hash to the same CID while being
     two different operations, and Go, whose decoder replaces it earlier still,
     would agree with neither.

  2. A dag-cbor BYTES SENTINEL — an object carrying both a `/` and a `bytes`
     member. The JS codec either crashes on it (a raw TypeError out of a
     protocol call) or silently re-reads it as a byte string; the Go reference
     writes an ordinary map. Reject it in both and neither has to guess.

  Anything else the codec refuses comes back as this module's own Error, never
  as a raw runtime exception: a library caller is entitled to the protocol's
  rejection vocabulary.

*/

describe('canonical encode — lone surrogates', () => {
  it('rejects a lone high surrogate in an object value', async () => {
    await expect(dagCborCanonicalEncode({ k: '\ud800' })).rejects.toThrow(/unpaired surrogate/);
  });

  it('rejects a lone low surrogate in an object value', async () => {
    await expect(dagCborCanonicalEncode({ k: '\udc00' })).rejects.toThrow(/unpaired surrogate/);
  });

  it('rejects a lone surrogate in a key, an array element, and a bare string', async () => {
    await expect(dagCborCanonicalEncode({ '\ud800': 1 })).rejects.toThrow(/unpaired surrogate/);
    await expect(dagCborCanonicalEncode(['ok', '\ud800'])).rejects.toThrow(/unpaired surrogate/);
    await expect(dagCborCanonicalEncode('\ud800')).rejects.toThrow(/unpaired surrogate/);
  });

  it('accepts a well-formed surrogate pair and a literal U+FFFD', async () => {
    // the pair is one astral codepoint, not two lone halves
    await expect(dagCborCanonicalEncode({ k: '😀' })).resolves.toBeDefined();
    await expect(dagCborCanonicalEncode({ k: '�' })).resolves.toBeDefined();
  });
});

describe('canonical encode — dag-cbor bytes sentinel', () => {
  it('rejects the shape that crashes the codec, as a protocol Error', async () => {
    const error = await dagCborCanonicalEncode({ '/': 0, bytes: 0 }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(TypeError);
    expect((error as Error).message).toMatch(/"\/" and "bytes"/);
  });

  it('rejects the shape the codec silently re-reads as a byte string', async () => {
    // this one does not crash — it encodes as CBOR bytes rather than as the map
    // the Go reference would write, which is the quieter half of the same fork
    await expect(dagCborCanonicalEncode({ '/': 'aa', bytes: 'bb' })).rejects.toThrow(
      /"\/" and "bytes"/,
    );
  });

  it('rejects it nested, and however the members are ordered', async () => {
    await expect(dagCborCanonicalEncode({ a: { bytes: 0, '/': 0 } })).rejects.toThrow(
      /"\/" and "bytes"/,
    );
  });

  it('accepts either member on its own', async () => {
    await expect(dagCborCanonicalEncode({ '/': 'bafyabc' })).resolves.toBeDefined();
    await expect(dagCborCanonicalEncode({ bytes: 'aa' })).resolves.toBeDefined();
  });
});
