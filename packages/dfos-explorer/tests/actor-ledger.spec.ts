import type { IndexContentRow } from '@metalabel/dfos-client';
import { describe, expect, it } from 'vitest';
import { contributedFromSignerPage } from '../src/lib/actor-ledger';

const row = (contentId: string, creatorDID: string): IndexContentRow => ({
  contentId,
  genesisCID: 'bafyGenesis',
  headCID: 'bafyHead',
  creatorDID,
  isDeleted: false,
  opCount: 1,
  genesisAt: '2026-01-01T00:00:00.000Z',
  headAt: '2026-01-02T00:00:00.000Z',
  currentDocumentCID: 'bafyDoc',
  publicRead: true,
  docSchema: null,
  title: null,
});

const ME = 'did:dfos:me';
const OTHER = 'did:dfos:other';

describe('contributedFromSignerPage — signer minus creator (spec subtraction)', () => {
  it('drops rows the DID created, keeps rows it only signed', () => {
    const page = contributedFromSignerPage(
      [row('c1', ME), row('c2', OTHER), row('c3', ME), row('c4', OTHER)],
      ME,
    );
    expect(page.rows.map((r) => r.contentId)).toEqual(['c2', 'c4']);
  });

  it('a signer page of only self-created chains contributes nothing', () => {
    const page = contributedFromSignerPage([row('c1', ME), row('c2', ME)], ME);
    expect(page.rows).toEqual([]);
    expect(page.truncated).toBe(false);
  });

  it('truncation keys off the RAW page length, NOT the subtracted length', () => {
    // a full 200-row signer page that subtracts down to 1 is STILL truncated —
    // keying off the post-subtraction length would under-report the omission.
    const rows = Array.from({ length: 200 }, (_, i) => row(`c${i}`, i === 0 ? OTHER : ME));
    const page = contributedFromSignerPage(rows, ME, 200);
    expect(page.rows).toHaveLength(1);
    expect(page.truncated).toBe(true);
  });

  it('a short raw page is not truncated', () => {
    const page = contributedFromSignerPage([row('c1', OTHER)], ME, 200);
    expect(page.truncated).toBe(false);
  });
});
