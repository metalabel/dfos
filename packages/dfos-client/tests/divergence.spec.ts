/*

  DIVERGENCE — the typed refusal, and the explicit way out

  A verified prefix is a PIN: once this client has proved a chain's first N
  operations, a relay answering with different operations at those positions is
  contradicting proof, not carrying news. `verify-forward.spec.ts` covers the
  refusal itself; this file covers the two things a stranded caller needs from
  it — a failure it can BRANCH on rather than string-match, and a discard narrow
  enough to un-stick one chain without forgetting anything else.

  The shape here is the real incident: a chain's HEAD operation is replaced, so
  the genesis (and therefore the DID) is untouched and only the tip contradicts.

*/

import { signIdentityOperation } from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import { DivergenceError, divergenceErrorFrom } from '../src/resolvers';
import { memoryStore } from '../src/store/memory';
import { buildContent, buildIdentity, fakePeerClient, ts, type RelayData } from './fixtures';

const RELAY = 'https://relay.test';

/** Rewrite an identity's history: same genesis, a DIFFERENT second operation. */
const rewriteHead = async (
  id: Awaited<ReturnType<typeof buildIdentity>>,
): Promise<{ log: string[]; headCID: string }> => {
  const replaced = await signIdentityOperation({
    operation: {
      version: 1,
      type: 'delete',
      previousOperationCID: id.genesisCID,
      createdAt: ts(-2),
    },
    signer: id.k.signer,
    keyId: id.k.keyId,
    identityDID: id.did,
  });
  return { log: [...id.genesisLog, replaced.jwsToken], headCID: replaced.operationCID };
};

describe('DivergenceError', () => {
  it('names the chain and both tips when an identity head is rewritten', async () => {
    const id = await buildIdentity({ rotate: true });
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.identity(id.did); // pins genesis + rotation

    const rewritten = await rewriteHead(id);
    data[RELAY]!.identities![id.did] = rewritten.log;

    const err = await client.identity(id.did).then(
      () => undefined,
      (e: unknown) => e,
    );
    const divergence = divergenceErrorFrom(err);
    expect(divergence).toBeInstanceOf(DivergenceError);
    expect(divergence!.chainType).toBe('identity');
    expect(divergence!.chainId).toBe(id.did);
    expect(divergence!.cachedHeadCID).toBe(id.headCID);
    expect(divergence!.liveHeadCID).toBe(rewritten.headCID);
    // the two tips are the whole point — a rewrite that changed nothing would
    // not diverge, so these must never come back equal
    expect(divergence!.cachedHeadCID).not.toBe(divergence!.liveHeadCID);
  });

  it('keeps the message the fan-out surfaces compatible with the old text', async () => {
    const id = await buildIdentity({ rotate: true });
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.identity(id.did);
    data[RELAY]!.identities![id.did] = (await rewriteHead(id)).log;

    await expect(client.identity(id.did)).rejects.toThrow(
      new RegExp(`identity log diverges from the verified cached prefix: ${id.did}`),
    );
  });

  it('reaches the divergence through a content read whose creator chain diverged', async () => {
    const creator = await buildIdentity({ rotate: true });
    const content = await buildContent(creator);
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: [...creator.log] },
        contents: { [content.contentId]: [...content.log] },
      },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.content(content.contentId);

    // the CREATOR's history is rewritten; the content chain itself is untouched
    data[RELAY]!.identities![creator.did] = (await rewriteHead(creator)).log;

    const err = await client.content(content.contentId).then(
      () => undefined,
      (e: unknown) => e,
    );
    const divergence = divergenceErrorFrom(err);
    // the failure names the chain that actually diverged, not the page's own id
    expect(divergence?.chainType).toBe('identity');
    expect(divergence?.chainId).toBe(creator.did);
  });

  it('is not raised for an ordinary verification failure', () => {
    expect(divergenceErrorFrom(new Error('all candidate logs failed verification: bad sig'))).toBe(
      undefined,
    );
    expect(divergenceErrorFrom('not an error at all')).toBe(undefined);
    expect(divergenceErrorFrom(undefined)).toBe(undefined);
  });
});

describe('discardCachedChain', () => {
  it('forgets one chain, and the next read folds the rewritten history cold', async () => {
    const id = await buildIdentity({ rotate: true });
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    const before = await client.identity(id.did);
    expect(before.value.isDeleted).toBe(false);

    const rewritten = await rewriteHead(id);
    data[RELAY]!.identities![id.did] = rewritten.log;
    await expect(client.identity(id.did)).rejects.toThrow(/diverges from the verified cached/);

    expect(await client.discardCachedChain('identity', id.did)).toBe(true);

    const after = await client.identity(id.did);
    expect(after.value.isDeleted).toBe(true); // the rewritten head, folded from genesis
    expect(after.value.did).toBe(id.did);
    expect(after.provenance.fromCache).toBe(false);
  });

  it('touches only the named chain — a second cached chain still resolves', async () => {
    const kept = await buildIdentity();
    const dropped = await buildIdentity({ rotate: true });
    const store = memoryStore();
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [kept.did]: [...kept.log], [dropped.did]: [...dropped.log] },
      },
    };
    const client = createClient({
      relays: [RELAY],
      store,
      peerClient: fakePeerClient(data),
    });
    await client.identity(kept.did);
    await client.identity(dropped.did);

    await client.discardCachedChain('identity', dropped.did);

    expect(await store.get(`identity:${dropped.did}`)).toBe(undefined);
    expect(await store.get(`identity:${kept.did}`)).not.toBe(undefined);
  });

  it('is idempotent, and a no-op for a chain that was never cached', async () => {
    const id = await buildIdentity();
    const data: Record<string, RelayData> = {
      [RELAY]: { identities: { [id.did]: [...id.log] } },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });

    expect(await client.discardCachedChain('identity', id.did)).toBe(true);
    expect(await client.discardCachedChain('content', 'did:dfos:nothing/1')).toBe(true);
    await client.identity(id.did);
    expect(await client.discardCachedChain('identity', id.did)).toBe(true);
    expect(await client.discardCachedChain('identity', id.did)).toBe(true);
    // still resolvable after two discards — the chain is on the relays, not here
    expect((await client.identity(id.did)).value.did).toBe(id.did);
  });

  it('discards the content key when asked for a content chain', async () => {
    const creator = await buildIdentity();
    const content = await buildContent(creator);
    const store = memoryStore();
    const client = createClient({
      relays: [RELAY],
      store,
      peerClient: fakePeerClient({
        [RELAY]: {
          identities: { [creator.did]: [...creator.log] },
          contents: { [content.contentId]: [...content.log] },
        },
      }),
    });
    await client.content(content.contentId);
    expect(await store.get(`content:${content.contentId}`)).not.toBe(undefined);

    await client.discardCachedChain('content', content.contentId);

    expect(await store.get(`content:${content.contentId}`)).toBe(undefined);
    // the creator identity's own pin is untouched — a different chain
    expect(await store.get(`identity:${creator.did}`)).not.toBe(undefined);
  });

  it('answers false when the configured store has no delete seam', async () => {
    const id = await buildIdentity();
    const map = new Map<string, unknown>();
    const client = createClient({
      relays: [RELAY],
      // the two-method Store shape a consumer may already have written
      store: {
        get: async (k) => map.get(k),
        set: async (k, v) => {
          map.set(k, v);
        },
      },
      peerClient: fakePeerClient({ [RELAY]: { identities: { [id.did]: [...id.log] } } }),
    });
    await client.identity(id.did);

    expect(await client.discardCachedChain('identity', id.did)).toBe(false);
    expect(map.has(`identity:${id.did}`)).toBe(true); // nothing was forgotten
  });
});

describe('memoryStore delete', () => {
  it('removes a key and shrugs at one that is absent', async () => {
    const store = memoryStore();
    await store.set('identity:a', { log: [] });
    expect(await store.get('identity:a')).not.toBe(undefined);

    await store.delete!('identity:a');
    expect(await store.get('identity:a')).toBe(undefined);

    await expect(store.delete!('identity:a')).resolves.toBe(undefined);
    await expect(store.delete!('never-written')).resolves.toBe(undefined);
  });
});
