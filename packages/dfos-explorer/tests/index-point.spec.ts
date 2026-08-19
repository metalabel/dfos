import type { IndexContentRow, IndexIdentityRow } from '@metalabel/dfos-client';
import { describe, expect, it } from 'vitest';
import { projectedName, projectedTitle, rowForContentId, rowForDid } from '../src/lib/index-point';

const DID = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
const OTHER = 'did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4';
const CONTENT = 'a3n7r3nde8e4keeak92rr3aeztftvc2';

const identity = (did: string, profile?: IndexIdentityRow['profile']): IndexIdentityRow => ({
  did,
  headCID: 'bafy1',
  opCount: 2,
  genesisAt: '2026-03-25T00:00:00.000Z',
  headAt: '2026-04-02T00:00:00.000Z',
  isDeleted: false,
  profile: profile ?? null,
});

const content = (contentId: string, over?: Partial<IndexContentRow>): IndexContentRow => ({
  contentId,
  genesisCID: 'bafy1',
  headCID: 'bafy2',
  creatorDID: DID,
  isDeleted: false,
  opCount: 2,
  genesisAt: '2026-03-25T00:00:00.000Z',
  headAt: '2026-04-02T00:00:00.000Z',
  currentDocumentCID: 'bafy3',
  publicRead: true,
  docSchema: 'https://schemas.dfos.com/post/v1',
  title: null,
  ...over,
});

describe('rowForDid — the point lookup is always key-matched', () => {
  it('returns the row that is actually about the DID', () => {
    expect(rowForDid([identity(OTHER), identity(DID)], DID)?.did).toBe(DID);
  });

  it('a relay that IGNORED `did=` served an unrelated page — that is not an answer', () => {
    // the pre-filter failure mode: an ordinary first page comes back, every row
    // about some other identity. Handing one back would be the relay answering a
    // question it never understood.
    expect(rowForDid([identity(OTHER)], DID)).toBeNull();
  });

  it('an empty page is nothing, not a claim of absence', () => {
    expect(rowForDid([], DID)).toBeNull();
  });
});

describe('rowForContentId — same key-match rule for content', () => {
  it('returns the row about the requested chain', () => {
    expect(rowForContentId([content(CONTENT)], CONTENT)?.contentId).toBe(CONTENT);
  });

  it('an unrelated page yields nothing', () => {
    expect(rowForContentId([content('zzz9zzz9zzz9zzz9zzz9zzz9zzz9zzz')], CONTENT)).toBeNull();
  });
});

describe('projectedName — only a relay-marked-PUBLIC name ever displays', () => {
  it('a public profile projection yields its name', () => {
    expect(
      projectedName(
        identity(DID, { anchor: CONTENT, publicRead: true, docSchema: null, name: 'asha' }),
      ),
    ).toBe('asha');
  });

  it('a NON-public projection never yields a name, even when the relay sent one', () => {
    // an unupgraded relay may still project it; it must not reach the screen
    expect(
      projectedName(
        identity(DID, { anchor: CONTENT, publicRead: false, docSchema: null, name: 'asha' }),
      ),
    ).toBe('');
  });

  it('no profile, a null name, or no row at all → nothing to show', () => {
    expect(projectedName(identity(DID))).toBe('');
    expect(
      projectedName(
        identity(DID, { anchor: CONTENT, publicRead: true, docSchema: null, name: null }),
      ),
    ).toBe('');
    expect(projectedName(null)).toBe('');
  });
});

describe('projectedTitle — the same rule for a content row', () => {
  it('a public chain yields its projected title', () => {
    expect(projectedTitle(content(CONTENT, { title: 'a post' }))).toBe('a post');
  });

  it('a non-public chain never surfaces a title', () => {
    expect(projectedTitle(content(CONTENT, { title: 'a post', publicRead: false }))).toBe('');
  });

  it('an unprojected title and a missing row are both nothing', () => {
    expect(projectedTitle(content(CONTENT))).toBe('');
    expect(projectedTitle(null)).toBe('');
  });
});
