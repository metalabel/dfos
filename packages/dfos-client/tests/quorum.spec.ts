/*

  QUORUM — distinct response digests

  `quorum: N` means N relays must return the SAME log (by content digest). The
  digest is derived from the ordered operation CIDs; agreement is provenance
  data, never a thrown error. On disagreement the best-supported group is still
  surfaced with `agreed: false`.

*/

import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import { digestOps } from '../src/transport';
import { buildIdentity, fakePeerClient, toEntries } from './fixtures';

const A = 'https://a.test';
const B = 'https://b.test';

describe('digestOps', () => {
  it('is stable for identical op sets and distinct for different ones', async () => {
    const id = await buildIdentity({ rotate: true });
    const full = toEntries(id.log).map((e) => ({ cid: e.cid, jwsToken: e.jwsToken }));
    const truncated = full.slice(0, 1);
    expect(digestOps(full)).toBe(digestOps([...full]));
    expect(digestOps(full)).not.toBe(digestOps(truncated));
    expect(digestOps([])).toBe(digestOps([]));
  });
});

describe('quorum', () => {
  it('quorum 1 is first-wins with agreement', async () => {
    const id = await buildIdentity();
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: id.log } },
      [B]: { identities: { [id.did]: id.log } },
    });
    const client = createClient({ relays: [A, B], quorum: 1, peerClient });

    const res = await client.identity(id.did);
    expect(res.provenance.agreed).toBe(true);
    expect(res.provenance.answeredBy).toBe(A);
    // first-wins: only the first relay is consulted
    expect(res.provenance.responses).toHaveLength(1);
  });

  it('quorum 2 agrees when both relays return the same log', async () => {
    const id = await buildIdentity({ rotate: true });
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: id.log } },
      [B]: { identities: { [id.did]: id.log } },
    });
    const client = createClient({ relays: [A, B], quorum: 2, peerClient });

    const res = await client.identity(id.did);
    expect(res.provenance.agreed).toBe(true);
    expect(res.provenance.responses).toHaveLength(2);
    const digests = new Set(res.provenance.responses.map((r) => r.digest));
    expect(digests.size).toBe(1);
  });

  it('quorum 2 fails to agree when relays diverge, but still surfaces an answer', async () => {
    const id = await buildIdentity({ rotate: true });
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: id.log } }, // full (genesis + rotation)
      [B]: { identities: { [id.did]: id.genesisLog } }, // genesis only — divergent tip
    });
    const client = createClient({ relays: [A, B], quorum: 2, peerClient });

    const res = await client.identity(id.did);
    expect(res.provenance.agreed).toBe(false);
    expect(res.provenance.responses).toHaveLength(2);
    const digests = new Set(res.provenance.responses.map((r) => r.digest));
    expect(digests.size).toBe(2);
    // the surfaced value is still a verified chain
    expect(res.value.did).toBe(id.did);
  });
});
