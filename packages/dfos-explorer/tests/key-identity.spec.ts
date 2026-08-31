/**
 * Key display identity — the truncation, and the kid fold.
 *
 * The fold has exactly two outcomes and the second one is the point: a kid whose
 * identity document is in hand resolves to the public key, and a kid whose
 * document is NOT in hand passes through unresolved. Never a guess, never a
 * lookup against a different chain's key set, never a key this tab did not read.
 * Everything below is the boundary between those two.
 *
 * The multikey fixtures are REAL — minted with the protocol's own encoder, the
 * same way tests/key-lookup.spec.ts does it — so an encoding change breaks these
 * rather than leaving them asserting a stale shape.
 */

import { encodeEd25519Multikey } from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import {
  EMPTY_KEY_DIRECTORY,
  keyDirectoryOf,
  resolveKidPubkey,
  roleKeys,
  shortPubkey,
  splitKid,
  type KeyDeclaration,
} from '../src/lib/key-identity';

/** A deterministic, distinct 32-byte key → a real `z6Mk…` multikey. */
const mk = (seed: number): string => encodeEd25519Multikey(new Uint8Array(32).fill(seed));

const A = mk(1);
const B = mk(2);
const DID = 'did:dfos:zQmWatwPfEqRuBFPfMPDCWHKFmSMkPq5jGwSLDNhVwFbSuA';
const OTHER = 'did:dfos:zQmXo91tWcJDbLjKZfFHrxpjM6yDRfhczHpDdU8Tvi5RURf';

// -----------------------------------------------------------------------------
// truncation — the reading density
// -----------------------------------------------------------------------------

describe('shortPubkey', () => {
  it('keeps ten leading and six trailing characters', () => {
    const key = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect(shortPubkey(key)).toBe('z6MkhaXgBZ…ta2doK');
    expect(shortPubkey(key).startsWith(key.slice(0, 10))).toBe(true);
    expect(shortPubkey(key).endsWith(key.slice(-6))).toBe(true);
  });

  it('drops to eight and four only when asked', () => {
    const key = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect(shortPubkey(key, true)).toBe('z6MkhaXg…2doK');
  });

  it('renders a real minted multikey without dropping its z6Mk prefix', () => {
    expect(shortPubkey(A).startsWith('z6Mk')).toBe(true);
  });

  // truncating a value shorter than the window would ADD an ellipsis to a
  // complete string — a key that reads as elided when it is whole
  it('leaves a short value whole', () => {
    expect(shortPubkey('z6Mk')).toBe('z6Mk');
  });
});

// -----------------------------------------------------------------------------
// the declaration list
// -----------------------------------------------------------------------------

describe('roleKeys', () => {
  it('flattens the three arrays in panel order', () => {
    const keys = roleKeys({
      authKeys: [{ id: 'key_1', publicKeyMultibase: A }],
      assertKeys: [{ id: 'key_2', publicKeyMultibase: B }],
      controllerKeys: [{ id: 'key_3', publicKeyMultibase: mk(3) }],
    });
    expect(keys.map((k) => k.id)).toEqual(['key_1', 'key_2', 'key_3']);
  });

  it('is total over a document declaring nothing', () => {
    expect(roleKeys({})).toEqual([]);
  });
});

describe('keyDirectoryOf', () => {
  it('holds the one identity it was given', () => {
    const dir = keyDirectoryOf(DID, [{ id: 'key_1', publicKeyMultibase: A }]);
    expect(dir.get(DID)).toHaveLength(1);
  });

  // a view with no chain folded yet must resolve NOTHING — an empty DID keying a
  // real key list would make every kid resolve against a nameless entry
  it('holds nothing for an empty DID', () => {
    expect(keyDirectoryOf('', [{ id: 'key_1', publicKeyMultibase: A }]).size).toBe(0);
  });
});

// -----------------------------------------------------------------------------
// splitKid
// -----------------------------------------------------------------------------

describe('splitKid', () => {
  it('splits a kid into its DID and fragment', () => {
    expect(splitKid(`${DID}#key_1`)).toEqual({ did: DID, fragment: 'key_1' });
  });

  it('names nothing for a kid with no fragment — a genesis op carries none', () => {
    expect(splitKid('')).toEqual({ did: '', fragment: '' });
    expect(splitKid(DID)).toEqual({ did: '', fragment: '' });
    expect(splitKid('#key_1')).toEqual({ did: '', fragment: '' });
  });
});

// -----------------------------------------------------------------------------
// the fold — resolved when the document is in hand, passed through when not
// -----------------------------------------------------------------------------

const keys: KeyDeclaration[] = [
  { id: 'key_1', publicKeyMultibase: A },
  { id: '#auth-1', publicKeyMultibase: B },
];
const dir = keyDirectoryOf(DID, keys);

describe('resolveKidPubkey — the document IS in hand', () => {
  it('resolves a bare-fragment declaration', () => {
    expect(resolveKidPubkey(`${DID}#key_1`, dir)).toBe(A);
  });

  it('resolves a declaration written with a leading hash', () => {
    expect(resolveKidPubkey(`${DID}#auth-1`, dir)).toBe(B);
  });

  it('resolves a declaration written as the full kid', () => {
    const full = keyDirectoryOf(DID, [{ id: `${DID}#key_9`, publicKeyMultibase: A }]);
    expect(resolveKidPubkey(`${DID}#key_9`, full)).toBe(A);
  });

  // the document is held and simply does not declare this slot — an absence, and
  // an absence is not a licence to return a neighbouring key
  it('returns null for a fragment the document does not declare', () => {
    expect(resolveKidPubkey(`${DID}#key_404`, dir)).toBeNull();
  });
});

describe('resolveKidPubkey — the document is NOT in hand', () => {
  it('passes through when no document at all is held', () => {
    expect(resolveKidPubkey(`${DID}#key_1`, EMPTY_KEY_DIRECTORY)).toBeNull();
  });

  // THE ONE THAT WOULD BE A FABRICATION: another identity's key set is not this
  // identity's, however identical the slot name is
  it('never resolves a kid against a different chain’s key set', () => {
    expect(resolveKidPubkey(`${OTHER}#key_1`, dir)).toBeNull();
  });

  it('passes through a kid with no fragment', () => {
    expect(resolveKidPubkey('', dir)).toBeNull();
    expect(resolveKidPubkey(DID, dir)).toBeNull();
  });
});
