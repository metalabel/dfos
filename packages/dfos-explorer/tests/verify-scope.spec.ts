/*

  VERIFY SCOPE — a verdict is filed under the relay set it was FOLDED against

  The tally on the landing panel is read per relay set (views/home.tsx), so which
  set a verdict is filed under is load-bearing: file it wrong and one relay's
  asserted op count is met by operations another relay served, which is the
  "fully verified locally" claim the scoping exists to stop.

  A fold is a network round trip, and the reader can change the relay set inside
  it. The key therefore has to be captured WITH the client — `getClient()` is
  memoized on the relay set, so the two are one decision — and not read again
  after the await, when it may name a set that never served these operations.

  The queue's collaborators are mocked here (and only here — mocking `./client`
  would break the failureStatus suite in verify-queue.spec.ts) so the fold can be
  held open across a relay switch.

*/

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { VerifyVerdict } from '../src/lib/db';

/** Every verdict the queue persisted, in order. */
const puts: VerifyVerdict[] = [];

/** The fake dfos-client the fold runs against — swapped per test. */
let client: {
  identity: (id: string) => Promise<{ value: { isDeleted: boolean } }>;
  log: (kind: string, id: string) => Promise<{ value: [] }>;
};

vi.mock('../src/lib/client', () => ({
  getClient: () => client,
  isVerificationFailure: () => false,
}));

vi.mock('../src/lib/db-instance', () => ({
  getDb: async () => ({
    getVerify: async () => undefined,
    putVerify: async (v: VerifyVerdict) => {
      puts.push(v);
    },
  }),
}));

vi.mock('../src/lib/sync-store', () => ({
  currentDbGeneration: () => 0,
  jitIndexChain: () => undefined,
  writeIfCurrent: async (_generation: number, fn: () => Promise<void>) => {
    await fn();
  },
}));

const { addRelay, relaySetKey, removeRelay } = await import('../src/lib/relays');
const { enqueueVerify } = await import('../src/lib/verify-queue');

const LATE_RELAY = 'https://late.example';

describe('a mid-flight relay switch does not re-file the verdict', () => {
  afterEach(() => {
    puts.length = 0;
    removeRelay(LATE_RELAY);
  });

  it('files the verdict under the set the fold RAN against, not the set at landing', async () => {
    const folding = relaySetKey();

    // hold the fold open: `entered` fires once the queue has taken its client
    // (and, with this fix, its relay key); `gate` releases the answer
    let entered!: () => void;
    let release!: () => void;
    const entry = new Promise<void>((r) => {
      entered = r;
    });
    const gate = new Promise<void>((r) => {
      release = r;
    });
    client = {
      identity: async () => {
        entered();
        await gate;
        return { value: { isDeleted: false } };
      },
      log: async () => {
        await gate;
        return { value: [] };
      },
    };

    enqueueVerify('identity', 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e');
    await entry;

    // the reader adds a relay while the fold is still in flight
    addRelay(LATE_RELAY);
    const landing = relaySetKey();
    expect(landing).not.toBe(folding);

    release();
    await vi.waitFor(() => expect(puts).toHaveLength(1));
    expect(puts[0]?.relaySet).toBe(folding);
    expect(puts[0]?.relaySet).not.toBe(landing);
  });
});
