import type { IndexContentRow } from '@metalabel/dfos-client';
import { describe, expect, it } from 'vitest';
import { contributedFromSignerPage, ledgerCounts } from '../src/lib/actor-ledger';

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
