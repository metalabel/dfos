import { describe, expect, it } from 'vitest';
import { creditLead, creditsTier, documentCredits } from '../src/components/credits';

describe('documentCredits — the fold’s answer is always a list', () => {
  it('extracts a document’s credits array', () => {
    const credits = [{ did: 'did:dfos:a', role: 'author' }];
    expect(documentCredits({ $schema: 'post/v1', credits })).toEqual(credits);
  });

  it('a document with NO credits yields an empty list, never a null', () => {
    // this is the P1: an absent field, an empty array, and a shape that cannot
    // carry credits are all VERIFIED FACTS about the document ("it credits
    // nobody"), and collapsing them into the same null the loading state uses is
    // what let a relay projection outlive the bytes that contradict it
    expect(documentCredits({ $schema: 'post/v1' })).toEqual([]);
    expect(documentCredits({ credits: [] })).toEqual([]);
    expect(documentCredits({ credits: 'not an array' })).toEqual([]);
  });

  it('a non-object document credits nobody — it has nowhere to say otherwise', () => {
    expect(documentCredits(null)).toEqual([]);
    expect(documentCredits('a string')).toEqual([]);
    expect(documentCredits(42)).toEqual([]);
    expect(documentCredits([{ did: 'did:dfos:a' }])).toEqual([]);
  });
});

describe('creditsTier — the fold always wins over the relay projection', () => {
  const entry = [{ did: 'did:dfos:a' }];

  it('folded entries render the verified tier, whatever the index says', () => {
    expect(creditsTier(entry, 0)).toBe('verified');
    expect(creditsTier(entry, 9)).toBe('verified');
  });

  it('a folded EMPTY list retires the projection — the P1 regression guard', () => {
    // the relay serves rows for a chain whose verified current document credits
    // nobody: stale projection, or a hostile one. The amber tier must not survive
    // its own contradiction by bytes this tab re-hashed.
    expect(creditsTier([], 5)).toBe('none');
    expect(creditsTier([], 0)).toBe('none');
  });

  it('the projection stands in ONLY while the fold has no answer', () => {
    expect(creditsTier(null, 3)).toBe('index');
  });

  it('no fold and no rows is simply nothing — credits are enrichment', () => {
    expect(creditsTier(null, 0)).toBe('none');
  });
});

describe('creditLead — a nameless credit still names someone', () => {
  const DID = 'did:dfos:27z77a722tacvrne3k7f6k6rzd9evkc';

  it('a named entry leads with its name', () => {
    expect(creditLead('Asha', DID)).toBe('name');
    expect(creditLead('Asha', undefined)).toBe('name');
  });

  it('a nameless entry leads with its DID, not with "unnamed credit"', () => {
    // `name` is optional on a credit entry and frequently absent; the DID is the
    // entry's actual identity and resolves to a public profile name through the
    // same chip every other surface uses
    expect(creditLead(undefined, DID)).toBe('did');
    expect(creditLead('', DID)).toBe('did');
    expect(creditLead('   ', DID)).toBe('did');
  });

  it('the muted placeholder is reserved for an entry with genuinely nothing', () => {
    expect(creditLead(undefined, undefined)).toBe('none');
    expect(creditLead('', '')).toBe('none');
    expect(creditLead('  ', '  ')).toBe('none');
  });
});
