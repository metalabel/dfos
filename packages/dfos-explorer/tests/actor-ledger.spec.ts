import type { IndexContentRow } from '@metalabel/dfos-client';
import { describe, expect, it } from 'vitest';
import {
  contributedFromSignerPage,
  ledgerCountPhrase,
  ledgerCounts,
  mergeWitnessRelations,
  witnessedFromPage,
} from '../src/lib/actor-ledger';

const row = (contentId: string, creatorDID: string, publicRead = true): IndexContentRow => ({
  contentId,
  genesisCID: 'bafyGenesis',
  headCID: 'bafyHead',
  creatorDID,
  isDeleted: false,
  opCount: 1,
  genesisAt: '2026-01-01T00:00:00.000Z',
  headAt: '2026-01-02T00:00:00.000Z',
  currentDocumentCID: 'bafyDoc',
  publicRead,
  docSchema: null,
  title: null,
});

const ME = 'did:dfos:me';
const OTHER = 'did:dfos:other';

describe('contributedFromSignerPage — signer minus creator (spec subtraction)', () => {
  it('drops rows the DID created, keeps rows it only signed', () => {
    const rows = contributedFromSignerPage(
      [row('c1', ME), row('c2', OTHER), row('c3', ME), row('c4', OTHER)],
      ME,
    );
    expect(rows.map((r) => r.contentId)).toEqual(['c2', 'c4']);
  });

  it('a signer page of only self-created chains contributes nothing', () => {
    expect(contributedFromSignerPage([row('c1', ME), row('c2', ME)], ME)).toEqual([]);
  });

  it('keeps gated rows — the actor axis lists existence, not just readable bytes', () => {
    const rows = contributedFromSignerPage([row('c1', OTHER, false), row('c2', ME, false)], ME);
    expect(rows.map((r) => r.contentId)).toEqual(['c1']);
  });

  it('is row-local, so per-page filtering equals filtering the whole', () => {
    // this is what licenses the lane's append-then-render loop: the identity view
    // subtracts each signer PAGE and concatenates rather than re-filtering.
    const p1 = [row('c1', ME), row('c2', OTHER)];
    const p2 = [row('c3', OTHER), row('c4', ME)];
    const perPage = [...contributedFromSignerPage(p1, ME), ...contributedFromSignerPage(p2, ME)];
    expect(perPage).toEqual(contributedFromSignerPage([...p1, ...p2], ME));
  });
});

describe('ledgerCounts — the loaded rows, split by read-visibility', () => {
  it('splits public from gated', () => {
    const counts = ledgerCounts([
      row('c1', ME),
      row('c2', ME, false),
      row('c3', ME, false),
      row('c4', ME),
      row('c5', ME, false),
    ]);
    expect(counts).toEqual({ total: 5, publicCount: 2, gatedCount: 3 });
  });

  it('an all-gated lane counts every row — existence is still listed', () => {
    expect(ledgerCounts([row('c1', ME, false), row('c2', ME, false)])).toEqual({
      total: 2,
      publicCount: 0,
      gatedCount: 2,
    });
  });

  it('an empty lane counts zero of everything', () => {
    expect(ledgerCounts([])).toEqual({ total: 0, publicCount: 0, gatedCount: 0 });
  });

  it('the two halves always sum to the total', () => {
    const rows = Array.from({ length: 37 }, (_, i) => row(`c${i}`, ME, i % 5 === 0));
    const counts = ledgerCounts(rows);
    expect(counts.publicCount + counts.gatedCount).toBe(counts.total);
    expect(counts.total).toBe(37);
  });
});

describe('ledgerCountPhrase — a lane naming its own size', () => {
  it('an exhausted cursor licenses the plain count', () => {
    expect(ledgerCountPhrase(212, 'chain', false)).toBe('212 chains');
    expect(ledgerCountPhrase(67, 'countersignature', false)).toBe('67 countersignatures');
    expect(ledgerCountPhrase(0, 'credential', false)).toBe('0 credentials');
  });

  it('one row is singular', () => {
    expect(ledgerCountPhrase(1, 'chain', false)).toBe('1 chain');
    expect(ledgerCountPhrase(1, 'credential', false)).toBe('1 credential');
  });

  it('a LIVE cursor makes the number a floor, and says so instead of naming a total', () => {
    // the relay's cursor says "more exists" and never "how many" — so the count
    // must not read as the corpus, whatever the noun would have been
    expect(ledgerCountPhrase(200, 'chain', true)).toBe('200 loaded so far');
    expect(ledgerCountPhrase(1, 'countersignature', true)).toBe('1 loaded so far');
    expect(ledgerCountPhrase(0, 'credential', true)).toBe('0 loaded so far');
  });
});

describe('witnessedFromPage — the relation re-filter', () => {
  const cs = (relation: string | null) => ({ relation });

  it('an unfiltered lane keeps every row', () => {
    const rows = [cs('approves'), cs(null), cs('endorses')];
    expect(witnessedFromPage(rows, null)).toEqual(rows);
  });

  it('keeps only exact matches — a relay that IGNORED relation= answers unfiltered', () => {
    const rows = [cs('approves'), cs('endorses'), cs(null), cs('approves')];
    expect(witnessedFromPage(rows, 'approves')).toEqual([cs('approves'), cs('approves')]);
  });

  it('an unroled row never answers a relation question', () => {
    expect(witnessedFromPage([cs(null)], 'approves')).toEqual([]);
  });

  it('is row-local, so per-page filtering equals filtering the whole', () => {
    // same property the Contributed subtraction has, and the same thing it
    // licenses: narrow each page, then append
    const p1 = [cs('approves'), cs('endorses')];
    const p2 = [cs(null), cs('approves')];
    expect([...witnessedFromPage(p1, 'approves'), ...witnessedFromPage(p2, 'approves')]).toEqual(
      witnessedFromPage([...p1, ...p2], 'approves'),
    );
  });
});

describe('mergeWitnessRelations — filter buttons across the pages loaded', () => {
  const cs = (relation: string | null) => ({ relation });

  it('harvests the distinct tags of a first page, sorted', () => {
    expect(mergeWitnessRelations([], [cs('endorses'), cs('approves'), cs('endorses')])).toEqual([
      'approves',
      'endorses',
    ]);
  });

  it('a later page WIDENS the set and never narrows it', () => {
    // replacing would let page 2 silently drop a button page 1 had earned
    expect(mergeWitnessRelations(['approves'], [cs('endorses')])).toEqual(['approves', 'endorses']);
    expect(mergeWitnessRelations(['approves', 'endorses'], [cs('approves')])).toEqual([
      'approves',
      'endorses',
    ]);
  });

  it('unroled rows offer no button', () => {
    expect(mergeWitnessRelations([], [cs(null), cs(null)])).toEqual([]);
  });

  it('the order a relay happens to serve never moves the buttons', () => {
    const a = mergeWitnessRelations([], [cs('c'), cs('a'), cs('b')]);
    const b = mergeWitnessRelations([], [cs('b'), cs('c'), cs('a')]);
    expect(a).toEqual(b);
    expect(a).toEqual(['a', 'b', 'c']);
  });
});
