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

    // the relay now serves the cached prefix plus the rotation op
    data[RELAY]!.identities![id.did] = [...id.log];
    const second = await client.identity(id.did);

    // verify-forward applied the new op — the rotated auth key is now present
    expect(second.value.authKeys).toHaveLength(2);
    expect(second.value.authKeys.map((k) => k.id)).toContain(id.rotatedKey!.keyId);
    expect(second.provenance.fromCache).toBe(false);
    expect(second.trust.unverifiable).toBeUndefined();

    // equals a from-scratch full verification of the whole log
    const full = await verifyIdentityChain({ didPrefix: 'did:dfos', log: id.log });
    expect(second.value).toEqual(full);
  });

  it('folds delete then restore forward and returns an active identity', async () => {
    const id = await buildIdentity({ restore: true });
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.genesisLog] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.identity(id.did);
    data[RELAY]!.identities![id.did] = [...id.log];

    const restored = await client.identity(id.did);
    expect(restored.value.isDeleted).toBe(false);
    expect(restored.value).toEqual(
      await verifyIdentityChain({ didPrefix: 'did:dfos', log: id.log }),
    );
  });

  it('a full relay log exactly matching the cache leaves the tip unverified', async () => {
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
    // ...but an unchanged full answer is a freshness CLAIM, not proof.
    expect(second.trust.unverifiable).toEqual(['tip']);
  });

  it('a relay behind the verified cached prefix falls back to the cache, never rolls back', async () => {
    const id = await buildIdentity({ rotate: true });
    const store = memoryStore();
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data) });
    await client.identity(id.did);

    // the relay regresses to genesis-only (data loss / mid-resync) — a
    // consistent-but-shorter answer carries no new information: the verified
    // cache stays the answer instead of failing the read or rolling back
    data[RELAY]!.identities![id.did] = [...id.genesisLog];
    const res = await client.identity(id.did);
    expect(res.value.authKeys).toHaveLength(2); // rotated state preserved
    expect(res.provenance.fromCache).toBe(true);
    expect(res.trust.unverifiable).toContain('tip');
    // and the trusted prefix in the store was not rolled back
    const cachedAfter = (await store.get(`identity:${id.did}`)) as { log: string[] };
    expect(cachedAfter.log).toHaveLength(id.log.length);
  });

  it('fails over past a behind relay to one that knows the cached prefix', async () => {
    const OTHER = 'https://relay-b.test';
    const id = await buildIdentity({ rotate: true });
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
      [OTHER]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({
      relays: [RELAY, OTHER],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.identity(id.did);

    // first relay regresses; the second still serves the full chain — the
    // behind relay must not shadow it into a cache fallback
    data[RELAY]!.identities![id.did] = [...id.genesisLog];
    const res = await client.identity(id.did);
    expect(res.value.authKeys).toHaveLength(2);
    expect(res.provenance.fromCache).toBe(false);
    expect(res.provenance.answeredBy).toBe(OTHER);
  });

  it('rejects a same-length relay log that diverges from the verified cached prefix', async () => {
    const cachedIdentity = await buildIdentity();
    const divergentIdentity = await buildIdentity();
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [cachedIdentity.did]: [...cachedIdentity.log] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.identity(cachedIdentity.did);

    data[RELAY]!.identities![cachedIdentity.did] = [...divergentIdentity.log];
    await expect(client.identity(cachedIdentity.did)).rejects.toThrow(
      /diverges from the verified cached prefix/,
    );
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
