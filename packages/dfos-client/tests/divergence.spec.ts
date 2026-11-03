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

import {
  signContentOperation,
  signIdentityOperation,
  type ContentOperation,
} from '@metalabel/dfos-protocol/chain';
import { createJws, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
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

// -----------------------------------------------------------------------------
// a content pin is a monotone UNION, not a prefix
// -----------------------------------------------------------------------------

describe('content pin — monotone union', () => {
  /** A creator with a second auth key, a genesis → update chain, and a
   *  creator-signed sibling of the update. */
  const setup = async () => {
    const creator = await buildIdentity({ rotate: true });
    const content = await buildContent(creator, { update: true });
    const sibling = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: creator.did,
        previousOperationCID: content.genesisCID,
        documentCID: 'bafkreiforkeddocument0000000000000000000000000000000000000000',
        baseDocumentCID: null,
        createdAt: ts(-3),
      },
      signer: creator.k.signer,
      kid: creator.kid,
    });
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: [...creator.log] },
        contents: { [content.contentId]: [...content.log, sibling.jwsToken] },
      },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    await client.content(content.contentId); // pins all three operations
    const serve = (log: string[]) => {
      data[RELAY]!.contents![content.contentId] = log;
    };
    return { creator, content, sibling, client, serve };
  };

  it('the same set served in another order is the cached set, not a divergence', async () => {
    const { content, sibling, client, serve } = await setup();
    serve([content.log[0]!, sibling.jwsToken, content.log[1]!]);
    const res = await client.content(content.contentId);
    expect(res.value.chain.headCID).toBe(sibling.operationCID);
    expect(res.trust.unverifiable).toEqual(['tip']);
  });

  it('a strict subset of the cached set is a relay behind: answered from the cache, never rolled back', async () => {
    const { content, sibling, client, serve } = await setup();
    serve([...content.log]);
    const res = await client.content(content.contentId);
    expect(res.provenance.fromCache).toBe(true);
    expect(res.value.chain.headCID).toBe(sibling.operationCID);
    expect(res.trust.unverifiable).toEqual(['tip']);
  });

  it('a cached op missing beside an op this client has not seen adds to the union', async () => {
    const { creator, content, sibling, client, serve } = await setup();
    const unseen = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: creator.did,
        previousOperationCID: sibling.operationCID,
        documentCID: 'bafkreiunseendocument0000000000000000000000000000000000000000',
        baseDocumentCID: null,
        createdAt: ts(-2),
      },
      signer: creator.k.signer,
      kid: creator.kid,
    });
    serve([content.log[0]!, sibling.jwsToken, unseen.jwsToken]);
    const res = await client.content(content.contentId);
    expect(res.value.chain.headCID).toBe(unseen.operationCID);
    const log = await client.log('content', content.contentId);
    expect(log.value.map((op) => op.cid).sort()).toEqual(
      [content.genesisCID, content.headCID, sibling.operationCID, unseen.operationCID].sort(),
    );
  });

  it('a relay appending one garbage token to a subset answer resolves from the union', async () => {
    const { content, sibling, client, serve } = await setup();
    const garbage = await createJws({
      header: {
        alg: 'EdDSA',
        typ: 'did:dfos:content-op',
        kid: 'did:dfos:nobody#k',
        cid: 'bafyreigarbage00000000000000000000000000000000000000000000',
      },
      payload: { junk: true, previousOperationCID: 'bafy-nowhere', createdAt: ts(-1) },
      sign: async () => new Uint8Array(64),
    });
    serve([content.log[0]!, garbage]);
    const res = await client.content(content.contentId);
    expect(res.value.chain.headCID).toBe(sibling.operationCID);
    expect(res.value.rejected.map((r) => r.cid)).toEqual([
      'bafyreigarbage00000000000000000000000000000000000000000000',
    ]);
    expect(res.trust.unverifiable).toEqual(['tip']);
  });

  it('a cached CID served with different bytes is a divergence', async () => {
    const { creator, content, sibling, client, serve } = await setup();
    // the same payload signed under the creator's OTHER auth key: same CID,
    // different token
    const decoded = decodeJwsUnsafe(content.log[1]!)!;
    const resigned = await signContentOperation({
      operation: decoded.payload as unknown as ContentOperation,
      signer: creator.rotatedKey!.signer,
      kid: `${creator.did}#${creator.rotatedKey!.keyId}`,
    });
    expect(resigned.operationCID).toBe(content.headCID);
    expect(resigned.jwsToken).not.toBe(content.log[1]);
    serve([content.log[0]!, resigned.jwsToken, sibling.jwsToken]);
    const err = await client.content(content.contentId).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(divergenceErrorFrom(err)?.chainType).toBe('content');
  });
});
