/**
 * The pure half of the key detail page: the standing fold behind the
 * has-ever-proved reverse lookup, and the sentinel probe that decides whether a
 * relay honours `key=` at all.
 *
 * The multikey fixtures are REAL — minted here with the protocol's own encoder
 * rather than pasted — so a change to the multikey encoding breaks these tests
 * instead of leaving them asserting against a stale shape.
 */

import { encodeEd25519Multikey } from '@metalabel/dfos-protocol/chain';
import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import {
  bodyFilterFromProbe,
  bodyFilterSupported,
  KEY_PROBE_MULTIBASE,
  supportedBodyFilterRelays,
} from '../src/lib/index-light';
import { toIdentityRows } from '../src/lib/index-raw';
import {
  classesOf,
  headKeysOf,
  keyStanding,
  voidClassesOf,
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
  voids: [],
  ...over,
});

// -----------------------------------------------------------------------------
// the standing fold — five states, and the two the fold must never conflate are
// `unchecked` (we failed to observe) and `void` (we observed a membership that
// does not work). Both would read as `rotated` under a naive fold, and both mean
// something else entirely.
// -----------------------------------------------------------------------------

describe('keyStanding', () => {
  it('is current when the head still carries the key, and names every class', () => {
    const s = keyStanding(A, head({ auth: [A], assert: [A, B], controller: [B] }));
    expect(s).toEqual({ kind: 'current', classes: ['auth', 'assert'], voidClasses: [] });
  });

  it('names classes in the identity panel’s order', () => {
    const s = keyStanding(A, head({ controller: [A], assert: [A], auth: [A] }));
    expect(s).toEqual({
      kind: 'current',
      classes: ['auth', 'assert', 'controller'],
      voidClasses: [],
    });
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

  // A key the head NAMES is not a key the head rotated away. `rotated out` would
  // tell a controller the opposite of what happened to their own chain.
  it('is void — never rotated — when the head names the key with no proof behind it', () => {
    const s = keyStanding(
      A,
      head({
        auth: [B],
        voids: [
          { key: A, role: 'auth' },
          { key: A, role: 'controller' },
        ],
      }),
    );
    expect(s).toEqual({ kind: 'void', classes: ['auth', 'controller'] });
    expect(s.kind).not.toBe('rotated');
  });

  it('carries the void roles alongside current, so a partly-proved key reads as both', () => {
    // proved into auth, named into assert without a proof covering that role
    const s = keyStanding(A, head({ auth: [A], voids: [{ key: A, role: 'assert' }] }));
    expect(s).toEqual({ kind: 'current', classes: ['auth'], voidClasses: ['assert'] });
  });

  it('ignores void memberships belonging to some other key', () => {
    expect(keyStanding(A, head({ auth: [B], voids: [{ key: B, role: 'assert' }] }))).toEqual({
      kind: 'rotated',
    });
  });

  it('keeps deletion the headline even when the head has void memberships', () => {
    expect(keyStanding(A, head({ isDeleted: true, voids: [{ key: A, role: 'auth' }] }))).toEqual({
      kind: 'deleted',
      classes: [],
    });
  });
});

describe('classesOf', () => {
  it('is empty for a key no head array carries', () => {
    expect(classesOf(C, head({ auth: [A], assert: [B] }))).toEqual([]);
  });
});

describe('voidClassesOf', () => {
  it('is empty on a fully-proved head', () => {
    expect(voidClassesOf(A, head({ auth: [A] }))).toEqual([]);
  });

  it('names the void roles in panel order and deduplicates them', () => {
    expect(
      voidClassesOf(
        A,
        head({
          voids: [
            { key: A, role: 'controller' },
            { key: A, role: 'auth' },
            { key: A, role: 'auth' },
          ],
        }),
      ),
    ).toEqual(['auth', 'controller']);
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
    // no `voidKeys` member at all — an older relay's state, or a cached fold that
    // predates it. Reads as no void memberships, which under-reports rather than
    // inventing one.
    expect(headKeysOf(identity)).toEqual({
      isDeleted: false,
      auth: [A],
      assert: [B],
      controller: [C],
      voids: [],
    });
  });

  it('flattens void memberships to (key, role) pairs', () => {
    const identity = {
      did: 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e',
      isDeleted: false,
      authKeys: [{ id: '#auth-1', type: 'Multikey', publicKeyMultibase: A }],
      assertKeys: [],
      controllerKeys: [],
      services: [],
      voidKeys: [
        {
          key: { id: '#assert-2', type: 'Multikey', publicKeyMultibase: B },
          role: 'assert',
          operationCID: 'bafyrei-op',
        },
      ],
    } as unknown as VerifiedIdentity;
    expect(headKeysOf(identity).voids).toEqual([{ key: B, role: 'assert' }]);
  });
});

// -----------------------------------------------------------------------------
// THE OLD-RELAY TRAP — a relay predating `key=` ignores it and answers with the
// UNFILTERED identity list. `key=` is specified as an opaque match with no format
// validation and therefore no 400, so the probe reads the BODY, not the status.
//
// The classifier is shared with the operations index's `signerKey=`, which has
// the identical shape and the identical trap; the sentinel is shared too. What
// that filter's lane does with the verdict is tests/key-ops.spec.ts.
// -----------------------------------------------------------------------------

describe('bodyFilterFromProbe', () => {
  it('reads rows-came-back as the param being IGNORED', () => {
    expect(bodyFilterFromProbe(200, 1)).toBe(false);
    expect(bodyFilterFromProbe(200, 25)).toBe(false);
  });

  it('reads a served empty page as the param being applied', () => {
    expect(bodyFilterFromProbe(200, 0)).toBe(true);
    expect(bodyFilterFromProbe(204, 0)).toBe(true);
  });

  it('is indeterminate for anything that is not a 2xx', () => {
    expect(bodyFilterFromProbe(501, 0)).toBeNull(); // no index at all
    expect(bodyFilterFromProbe(404, 0)).toBeNull();
    expect(bodyFilterFromProbe(500, 0)).toBeNull();
    expect(bodyFilterFromProbe(400, 0)).toBeNull();
    expect(bodyFilterFromProbe(0, 0)).toBeNull(); // unreachable / aborted
  });
});

// THE VERDICT IS A RELAY SET, NOT A YES. Index queries fail over relay by relay
// and take the first 2xx from whoever answers, so "some relay supports it" cannot
// gate the query: the relay that answers may not be the relay that was probed.
describe('supportedBodyFilterRelays', () => {
  const probe = (relay: string, status: number, rows: number) => ({ relay, status, rows });

  it('keeps only the relays whose OWN probe said supported', () => {
    expect(supportedBodyFilterRelays([probe('a', 200, 0)])).toEqual(['a']);
    expect(supportedBodyFilterRelays([probe('a', 200, 3)])).toEqual([]);
  });

  it('excludes an old relay standing beside a good one — it must never be asked', () => {
    // the bug this shape exists to make impossible: `a` ignores the filter and
    // would answer an unfiltered page, and a failover would let it
    expect(supportedBodyFilterRelays([probe('a', 200, 5), probe('b', 200, 0)])).toEqual(['b']);
  });

  it('excludes an INDETERMINATE relay rather than deferring to it', () => {
    // unreachable at probe time says nothing about what it serves — and if it
    // comes back up mid-session the failover would reach it. Not in the set.
    expect(
      supportedBodyFilterRelays([probe('a', 0, 0), probe('b', 501, 0), probe('c', 200, 0)]),
    ).toEqual(['c']);
  });

  it('preserves configured order so failover still walks the preference', () => {
    expect(
      supportedBodyFilterRelays([probe('a', 200, 0), probe('b', 500, 0), probe('c', 204, 0)]),
    ).toEqual(['a', 'c']);
  });

  it('degrades to the empty set when nothing is definitive', () => {
    expect(supportedBodyFilterRelays([])).toEqual([]);
    expect(supportedBodyFilterRelays([probe('a', 0, 0)])).toEqual([]);
    expect(supportedBodyFilterRelays([probe('a', 501, 0), probe('b', 502, 0)])).toEqual([]);
  });
});

describe('bodyFilterSupported — the UI gate over the set', () => {
  it('holds null while the probe is in flight', () => {
    expect(bodyFilterSupported(null)).toBeNull();
  });

  it('is supported only when some relay can actually be asked', () => {
    expect(bodyFilterSupported(['https://r'])).toBe(true);
    expect(bodyFilterSupported([])).toBe(false);
  });
});

describe('KEY_PROBE_MULTIBASE', () => {
  // the sentinel is sent to a live relay, so it must look like a key rather than
  // like garbage — a well-formed value can never be rejected on format
  it('is a well-formed Ed25519 multikey', () => {
    expect(KEY_PROBE_MULTIBASE).toMatch(/^z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
    expect(KEY_PROBE_MULTIBASE).toHaveLength(48);
  });

  it('is not one of the fixture keys', () => {
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
