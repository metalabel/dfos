/*

  CACHE-THE-LOG + VERIFY-FORWARD

  The one earned abstraction: cache the LOG, then verify FORWARD from the trusted
  prefix using the protocol's O(1) extension verifiers when new ops arrive. A
  rotation costs one incremental op; the cached result is never stale-wrong and
  always equals a full re-verification.

*/

import {
  decodeMultikey,
  verifyContentChain,
  verifyIdentityChain,
} from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import { memoryStore } from '../src/store/memory';
import { buildContent, buildIdentity, fakePeerClient, type RelayData } from './fixtures';

const RELAY = 'https://relay.test';

describe('identity verify-forward', () => {
  it('folds a later rotation onto a cached genesis and matches full verification', async () => {
    const id = await buildIdentity({ rotate: true });
    // relay initially serves only the genesis op
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.genesisLog] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });

    const first = await client.identity(id.did);
    expect(first.value.authKeys).toHaveLength(1);

    // the rotation op arrives at the relay
    data[RELAY]!.identities![id.did] = [...id.log];
    const second = await client.identity(id.did);

    // verify-forward applied the new op — the rotated auth key is now present
    expect(second.value.authKeys).toHaveLength(2);
    expect(second.value.authKeys.map((k) => k.id)).toContain(id.rotatedKey!.keyId);
    expect(second.provenance.fromCache).toBe(false);

    // equals a from-scratch full verification of the whole log
    const full = await verifyIdentityChain({ didPrefix: 'did:dfos', log: id.log });
    expect(second.value).toEqual(full);
  });

  it('a caught-up relay returns the cached state — but tip stays an unproven CLAIM', async () => {
    const id = await buildIdentity();
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });

    const first = await client.identity(id.did);
    expect(first.trust.unverifiable).toBeUndefined(); // fresh full fetch

    const second = await client.identity(id.did);
    expect(second.value).toEqual(first.value);
    expect(second.provenance.fromCache).toBe(false); // relays DID answer...
    // ...but an empty delta against a cached head is a freshness CLAIM, not
    // proof — a relay that never saw our head answers the same empty page.
    // Tip freshness is never proven in v1.
    expect(second.trust.unverifiable).toEqual(['tip']);
  });
});

describe('content verify-forward', () => {
  it('folds a later content update onto a cached genesis and matches full verification', async () => {
    const creator = await buildIdentity();
    const content = await buildContent(creator, { update: true });
    const genesisContentLog = content.log.slice(0, 1);

    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: [...creator.log] },
        contents: { [content.contentId]: [...genesisContentLog] },
      },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });

    const first = await client.content(content.contentId);
    expect(first.value.chain.length).toBe(1);

    // the update op arrives
    data[RELAY]!.contents![content.contentId] = [...content.log];
    const second = await client.content(content.contentId);
    expect(second.value.chain.length).toBe(2);
    expect(second.value.chain.headCID).toBe(content.headCID);

    // matches a full from-scratch verification
    const resolveKey = async (kid: string): Promise<Uint8Array> => {
      if (kid !== creator.kid) throw new Error(`unexpected kid ${kid}`);
      return decodeMultikey(creator.k.key.publicKeyMultibase).keyBytes;
    };
    const full = await verifyContentChain({ log: content.log, resolveKey });
    expect(second.value.chain).toEqual(full);
  });
});
