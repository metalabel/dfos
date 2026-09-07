import { describe, expect, it } from 'vitest';
import {
  cacheIsFresh,
  PROFILE_TTL_MS,
  publicProfileOf,
  resolveProfileVerdict,
  trimCache,
} from '../src/lib/did-profiles';

const DID = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
const profileDoc = {
  $schema: 'https://schemas.dfos.com/profile/v1',
  name: 'Ada',
  description: 'writes programs',
  avatar: { uri: 'attachment://a', cid: 'bafk1', href: 'https://cdn.example/a' },
};

describe('publicProfileOf — the privacy + integrity gate', () => {
  it('a public, integral profile/v1 yields its name', () => {
    expect(publicProfileOf(DID, profileDoc, true)).toEqual({
      did: DID,
      name: 'Ada',
      description: 'writes programs',
      avatar: { uri: 'attachment://a', cid: 'bafk1', href: 'https://cdn.example/a' },
    });
  });

  it('NEVER yields a name when the bytes do not re-hash to the committed CID', () => {
    // the relay served something other than what the chain commits to — the whole
    // point of the gate. A name here would be a relay writing someone's identity.
    expect(publicProfileOf(DID, profileDoc, false)).toBeNull();
  });

  it('a non-profile document yields nothing, however integral', () => {
    expect(
      publicProfileOf(DID, { $schema: 'https://schemas.dfos.com/post/v1', title: 'hi' }, true),
    ).toBeNull();
  });

  it('a nameless or blank-named profile yields nothing (a chip has nothing to show)', () => {
    expect(publicProfileOf(DID, { $schema: profileDoc.$schema }, true)).toBeNull();
    expect(publicProfileOf(DID, { $schema: profileDoc.$schema, name: '   ' }, true)).toBeNull();
  });

  it('undecodable / absent bytes yield nothing', () => {
    expect(publicProfileOf(DID, null, true)).toBeNull();
    expect(publicProfileOf(DID, undefined, true)).toBeNull();
    expect(publicProfileOf(DID, 'not a document', true)).toBeNull();
  });

  it('an avatar that is not a Media object is dropped, not half-rendered', () => {
    const p = publicProfileOf(DID, { ...profileDoc, avatar: 'https://evil/a.png' }, true);
    expect(p?.avatar).toBeNull();
  });
});

describe('cacheIsFresh — a cached name is never trusted forever', () => {
  const now = 1_800_000_000_000;
  it('inside the TTL is fresh', () => {
    expect(cacheIsFresh(now - 1000, now)).toBe(true);
    expect(cacheIsFresh(now - (PROFILE_TTL_MS - 1), now)).toBe(true);
  });

  it('at or past the TTL is stale (a profile chain can be updated)', () => {
    expect(cacheIsFresh(now - PROFILE_TTL_MS, now)).toBe(false);
    expect(cacheIsFresh(now - PROFILE_TTL_MS * 3, now)).toBe(false);
  });

  it('a future timestamp (clock skew / tampering) reads as stale, not fresh forever', () => {
    expect(cacheIsFresh(now + 1000, now)).toBe(false);
  });
});

describe('trimCache — the persisted cache is bounded', () => {
  it('keeps everything under the cap', () => {
    const entries = { a: { n: 'A', d: '', at: 1 }, b: { n: 'B', d: '', at: 2 } };
    expect(trimCache(entries, 5)).toBe(entries);
  });

  it('keeps the most recently resolved and drops the oldest', () => {
    const trimmed = trimCache(
      {
        old: { n: 'old', d: '', at: 1 },
        mid: { n: 'mid', d: '', at: 2 },
        new: { n: 'new', d: '', at: 3 },
      },
      2,
    );
    expect(Object.keys(trimmed).sort()).toEqual(['mid', 'new']);
  });
});

// M42: every failure used to collapse to `null`, which a row prints as the flat
// factual assertion "no public profile". An unreachable relay is not that claim.
describe('resolveProfileVerdict — absence and unavailability are different answers', () => {
  const anchored = {
    value: {
      services: [
        { type: 'ContentAnchor', id: 'profile', anchor: 'ct7kkfz7ehzvv6fzvate9rz2874nc3e' },
      ],
    },
  };
  const rejects = () => Promise.reject(new Error('relay unreachable'));

  it('is unavailable when the identity chain itself did not resolve', async () => {
    expect(await resolveProfileVerdict(DID, { identity: rejects, document: rejects })).toBe(
      'unavailable',
    );
  });

  it('is none when the identity resolved and anchors no profile', async () => {
    expect(
      await resolveProfileVerdict(DID, {
        identity: async () => ({ value: { services: [] } }),
        document: rejects,
      }),
    ).toBeNull();
  });

  // the privacy invariant, unchanged: bytes no relay serves to an anonymous read
  // ARE "no public profile" — that is what public-read means empirically
  it('is none when the anchored document is not served publicly', async () => {
    expect(
      await resolveProfileVerdict(DID, { identity: async () => anchored, document: rejects }),
    ).toBeNull();
  });

  it('is none when the served bytes fail the integrity re-hash', async () => {
    expect(
      await resolveProfileVerdict(DID, {
        identity: async () => anchored,
        document: async () => ({ value: { decoded: profileDoc, integrity: false } }),
      }),
    ).toBeNull();
  });

  it('resolves the public profile when every beat lands', async () => {
    expect(
      await resolveProfileVerdict(DID, {
        identity: async () => anchored,
        document: async () => ({ value: { decoded: profileDoc, integrity: true } }),
      }),
    ).toMatchObject({ did: DID, name: 'Ada' });
  });
});
