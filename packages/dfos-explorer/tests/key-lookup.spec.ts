/**
 * The pure half of the key detail page: the has-ever-declared standing fold, and
 * the sentinel probe that decides whether a relay honours `key=` at all.
 *
 * The multikey fixtures are REAL — minted here with the protocol's own encoder
 * rather than pasted — so a change to the multikey encoding breaks these tests
 * instead of leaving them asserting against a stale shape.
 */

import { encodeEd25519Multikey } from '@metalabel/dfos-protocol/chain';
import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import { decideKeyFilter, KEY_PROBE_MULTIBASE, keyFilterFromProbe } from '../src/lib/index-light';
import { toIdentityRows } from '../src/lib/index-raw';
import {
  classesOf,
  headKeysOf,
  keyStanding,
  type HeadKeys,
  type KeyStanding,
} from '../src/lib/key-standing';

/** A deterministic, distinct 32-byte key → a real `z6Mk…` multikey. */
const mk = (seed: number): string =>
  encodeEd25519Multikey(new Uint8Array(32).fill(seed === 0 ? 1 : seed));

const A = mk(1);
const B = mk(2);
const C = mk(3);

const head = (over: Partial<HeadKeys> = {}): HeadKeys => ({
  isDeleted: false,
  auth: [],
  assert: [],
  controller: [],
  ...over,
});

// -----------------------------------------------------------------------------
// the standing fold — four states, and the fourth is the point
// -----------------------------------------------------------------------------

describe('keyStanding', () => {
  it('is current when the head still declares the key, and names every class', () => {
    const s = keyStanding(A, head({ auth: [A], assert: [A, B], controller: [B] }));
    expect(s).toEqual({ kind: 'current', classes: ['auth', 'assert'] });
  });

  it('names classes in the identity panel’s order', () => {
    const s = keyStanding(A, head({ controller: [A], assert: [A], auth: [A] }));
    expect(s).toEqual({ kind: 'current', classes: ['auth', 'assert', 'controller'] });
  });

  it('is rotated out when the chain verifies and the head no longer carries it', () => {
    expect(keyStanding(A, head({ auth: [B], controller: [C] }))).toEqual({ kind: 'rotated' });
  });

  it('reports deletion over key state, and still records the classes it found', () => {
    expect(keyStanding(A, head({ isDeleted: true, controller: [A] }))).toEqual({
      kind: 'deleted',
      classes: ['controller'],
    });
    // rotated out and THEN deleted — deletion is still the headline
    expect(keyStanding(A, head({ isDeleted: true, controller: [B] }))).toEqual({
      kind: 'deleted',
      classes: [],
    });
  });

  it('is unchecked — never rotated — when the chain did not resolve', () => {
    const s = keyStanding(A, null, 'no relay served this identity');
    expect(s).toEqual({ kind: 'unchecked', reason: 'no relay served this identity' });
    // the distinction the whole label exists for: an unread chain is not evidence
    // that the key was rotated away
    expect((s as KeyStanding).kind).not.toBe('rotated');
  });

  it('matches byte-for-byte, like the relay filter it labels', () => {
    expect(keyStanding(A, head({ auth: [A.toLowerCase()] })).kind).toBe('rotated');
    expect(keyStanding(A, head({ auth: [`${A} `] })).kind).toBe('rotated');
    expect(keyStanding(A, head({ auth: [A.slice(0, -1)] })).kind).toBe('rotated');
  });
});

describe('classesOf', () => {
  it('is empty for a key no head array carries', () => {
    expect(classesOf(C, head({ auth: [A], assert: [B] }))).toEqual([]);
  });
});

describe('headKeysOf', () => {
  it('flattens a verified identity to its multibase strings', () => {
    const identity = {
      did: 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e',
      isDeleted: false,
      authKeys: [{ id: '#auth-1', type: 'Multikey', publicKeyMultibase: A }],
      assertKeys: [{ id: '#assert-1', type: 'Multikey', publicKeyMultibase: B }],
      controllerKeys: [{ id: '#ctrl-1', type: 'Multikey', publicKeyMultibase: C }],
      services: [],
    } as unknown as VerifiedIdentity;
    expect(headKeysOf(identity)).toEqual({
      isDeleted: false,
      auth: [A],
      assert: [B],
      controller: [C],
    });
  });
});

// -----------------------------------------------------------------------------
// THE OLD-RELAY TRAP — a relay predating `key=` ignores it and answers with the
// UNFILTERED identity list. `key=` is specified as an opaque match with no format
// validation and therefore no 400, so the probe reads the BODY, not the status.
// -----------------------------------------------------------------------------

describe('keyFilterFromProbe', () => {
  it('reads rows-came-back as the param being IGNORED', () => {
    expect(keyFilterFromProbe(200, 1)).toBe(false);
    expect(keyFilterFromProbe(200, 25)).toBe(false);
  });

  it('reads a served empty page as the param being applied', () => {
    expect(keyFilterFromProbe(200, 0)).toBe(true);
    expect(keyFilterFromProbe(204, 0)).toBe(true);
  });

  it('is indeterminate for anything that is not a 2xx', () => {
    expect(keyFilterFromProbe(501, 0)).toBeNull(); // no index at all
    expect(keyFilterFromProbe(404, 0)).toBeNull();
    expect(keyFilterFromProbe(500, 0)).toBeNull();
    expect(keyFilterFromProbe(400, 0)).toBeNull();
    expect(keyFilterFromProbe(0, 0)).toBeNull(); // unreachable / aborted
  });
});

describe('decideKeyFilter', () => {
  it('takes the first DEFINITIVE relay, mirroring query failover', () => {
    expect(decideKeyFilter([{ status: 200, rows: 0 }])).toBe(true);
    expect(decideKeyFilter([{ status: 200, rows: 3 }])).toBe(false);
    expect(
      decideKeyFilter([
        { status: 0, rows: 0 },
        { status: 501, rows: 0 },
        { status: 200, rows: 0 },
      ]),
    ).toBe(true);
    // an old relay FIRST loses to nothing behind it — it is the one that serves
    expect(
      decideKeyFilter([
        { status: 200, rows: 5 },
        { status: 200, rows: 0 },
      ]),
    ).toBe(false);
  });

  it('degrades to unsupported when nothing is definitive', () => {
    expect(decideKeyFilter([])).toBe(false);
    expect(decideKeyFilter([{ status: 0, rows: 0 }])).toBe(false);
    expect(
      decideKeyFilter([
        { status: 501, rows: 0 },
        { status: 502, rows: 0 },
      ]),
    ).toBe(false);
  });
});

describe('KEY_PROBE_MULTIBASE', () => {
  // the sentinel is sent to a live relay, so it must look like a key rather than
  // like garbage — a well-formed value can never be rejected on format
  it('is a well-formed Ed25519 multikey', () => {
    expect(KEY_PROBE_MULTIBASE).toMatch(/^z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
    expect(KEY_PROBE_MULTIBASE).toHaveLength(48);
  });

  it('is not a key any of the fixtures declares', () => {
    expect([A, B, C]).not.toContain(KEY_PROBE_MULTIBASE);
  });
});

// -----------------------------------------------------------------------------
// row coercion — a relay's JSON is untrusted input
// -----------------------------------------------------------------------------

describe('toIdentityRows', () => {
  it('drops rows that name no identity', () => {
    expect(toIdentityRows({ identities: [{ headCID: 'bafy1' }, { did: 'did:dfos:a' }] })).toEqual([
      {
        did: 'did:dfos:a',
        headCID: '',
        opCount: 0,
        genesisAt: '',
        headAt: '',
        isDeleted: false,
        profile: null,
      },
    ]);
  });

  it('keeps the index’s honest nulls on a withheld profile projection', () => {
    const [row] = toIdentityRows({
      identities: [
        {
          did: 'did:dfos:a',
          headCID: 'bafy1',
          opCount: 3,
          genesisAt: '2026-01-01T00:00:00Z',
          headAt: '2026-02-01T00:00:00Z',
          isDeleted: true,
          profile: { anchor: 'abc', publicRead: false, docSchema: null, name: null },
        },
      ],
    });
    expect(row?.isDeleted).toBe(true);
    expect(row?.profile).toEqual({
      anchor: 'abc',
      publicRead: false,
      docSchema: null,
      name: null,
    });
  });

  it('is empty for a body that is not an identities page', () => {
    expect(toIdentityRows(null)).toEqual([]);
    expect(toIdentityRows({})).toEqual([]);
    expect(toIdentityRows({ identities: 'nope' })).toEqual([]);
  });
});
