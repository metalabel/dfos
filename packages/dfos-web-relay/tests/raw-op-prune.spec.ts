import { describe, expect, it } from 'vitest';
import { MemoryRelayStore } from '../src';

// R4 hardening: a permanent rejection must DELETE the raw op, not flip its status.
// Keeping rejected rows let an unauthenticated submitter grow the content-addressed
// raw store without bound by mutating one byte per op to mint a fresh CID. The
// deletion is proven by re-putting the same CID — putRawOp is put-if-absent, so a
// pending row reappears only if the original was actually gone; a status flip would
// leave the row present and the re-put would be a no-op, keeping the count at 0.
describe('R4: raw-op prune', () => {
  it('markOpRejected deletes the raw op row, not just flips its status', async () => {
    const store = new MemoryRelayStore();
    const cid = 'bafyExampleRawOpPruneCID';

    await store.putRawOp(cid, 'jws-token-1');
    expect(await store.countUnsequenced()).toBe(1);

    await store.markOpRejected(cid, 'permanent: bad signature');
    expect(await store.countUnsequenced()).toBe(0);

    // Re-put the same CID — only re-creates a pending row if the reject deleted it.
    await store.putRawOp(cid, 'jws-token-2');
    expect(await store.countUnsequenced()).toBe(1);
  });
});
