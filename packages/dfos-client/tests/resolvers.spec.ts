import { isDependencyMissing } from '@metalabel/dfos-protocol';
import {
  decodeMultikey,
  signContentOperation,
  signIdentityOperation,
  verifyContentDag,
  type ContentOperation,
} from '@metalabel/dfos-protocol/chain';
import { createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import { createJws, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import type {
  Callbacks,
  EffectiveIdentity,
  EverProvedIdentity,
  Resolved,
  ResolvedContent,
  RevChecker,
} from '../src';
import { createClient } from '../src/client';
import { divergenceErrorFrom } from '../src/resolvers';
import { memoryStore } from '../src/store/memory';
import {
  buildContent,
  buildIdentity,
  cidOf,
  fakePeerClient,
  ts,
  type BuiltIdentity,
  type RelayData,
} from './fixtures';

// Checked by the package typecheck, without invoking a resolver at runtime.
const checkResolutionTypes = (
  callbacks: Callbacks,
  effective: EffectiveIdentity,
  historical: EverProvedIdentity,
) => {
  // @ts-expect-error Ever-proved keys cannot authorize at a time basis.
  const asOf: Callbacks['resolveIdentity'] = callbacks.resolveClaimantIdentity;
  // @ts-expect-error Effective state does not include all historically proved keys.
  const claimant: Callbacks['resolveClaimantIdentity'] = callbacks.resolveIdentity;
  // @ts-expect-error Historical state cannot be used as head state.
  const head: EffectiveIdentity = historical;
  // @ts-expect-error Effective state is not an ever-proved projection.
  const proved: EverProvedIdentity = effective;
  return { asOf, claimant, head, proved };
};
void checkResolutionTypes;

describe('identity resolution contexts', () => {
  it('retains a proved-then-voided key only in the ever-proved projection', async () => {
    const identity = await buildIdentity({ rotate: true });
    const removed = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'update',
        previousOperationCID: identity.headCID,
        authKeys: [identity.k.key],
        assertKeys: [identity.k.key],
        controllerKeys: [identity.k.key],
        createdAt: ts(-4),
      },
      signer: identity.k.signer,
      keyId: identity.k.keyId,
      identityDID: identity.did,
    });
    // Reintroduction without a fresh possession proof is void even though this
    // key was proved at an earlier position in the chain.
    const voided = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'update',
        previousOperationCID: removed.operationCID,
        authKeys: [identity.k.key, identity.rotatedKey!.key],
        assertKeys: [identity.k.key],
        controllerKeys: [identity.k.key],
        createdAt: ts(-3),
      },
      signer: identity.k.signer,
      keyId: identity.k.keyId,
      identityDID: identity.did,
    });
    const relay = 'https://relay.test';
    const client = createClient({
      relays: [relay],
      peerClient: fakePeerClient({
        [relay]: {
          identities: {
            [identity.did]: [...identity.log, removed.jwsToken, voided.jwsToken],
          },
        },
      }),
    });
    const callbacks = client.callbacks();
    const effective = await callbacks.resolveIdentity(identity.did);
    const historical = await callbacks.resolveClaimantIdentity(identity.did);
    expect(effective).toBeDefined();
    expect(historical?.resolution).toBe('ever-proved');
    expect(effective?.authKeys.map((key) => key.id)).toEqual([identity.k.keyId]);
    expect(effective?.voidKeys).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: identity.rotatedKey!.key, role: 'auth' }),
      ]),
    );
    expect(historical?.authKeys.map((key) => key.id)).toEqual([
      identity.k.keyId,
      identity.rotatedKey!.keyId,
    ]);
    expect((await client.identity(identity.did)).value.authKeys).toEqual(effective?.authKeys);
  });
});

// -----------------------------------------------------------------------------
// the basis is an ANSWER, not just a lookup parameter
// -----------------------------------------------------------------------------

describe('historical resolution — determinate verdicts survive', () => {
  const RELAY = 'https://relay.test';

  const clientFor = (identity: Awaited<ReturnType<typeof buildIdentity>>) =>
    createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({ [RELAY]: { identities: { [identity.did]: identity.log } } }),
    });

  it('a basis before genesis THROWS rather than reading as "identity not found"', async () => {
    // `undefined` is what every protocol consumer reads as a retryable
    // dependency miss. No relay can ever deliver state for an instant that
    // predates the chain, so the answer is final and has to say so.
    const identity = await buildIdentity();
    const { resolveIdentity } = clientFor(identity).callbacks();
    await expect(resolveIdentity(identity.did, ts(-600))).rejects.toThrow(/no state as of/);
  });

  it('an unresolvable chain is still an ordinary miss (undefined)', async () => {
    const identity = await buildIdentity();
    const other = await buildIdentity();
    const { resolveIdentity } = clientFor(identity).callbacks();
    await expect(resolveIdentity(other.did, ts(-1))).resolves.toBeUndefined();
  });

  it('marks a re-walked historical state DETERMINATE, like the relay resolver does', async () => {
    // the chain runs PAST the basis, so no operation the basis names can still
    // arrive: a key missing from this state is a verdict, not a pending sync
    const identity = await buildIdentity({ rotate: true });
    const { resolveIdentity } = clientFor(identity).callbacks();
    const asOf = await resolveIdentity(identity.did, ts(-7));
    expect(asOf?.basisDeterminate).toBe(true);
    // the rotation is dated after the basis, so its key is absent from this state
    expect(asOf?.authKeys.map((k) => k.id)).toEqual([identity.k.keyId]);
  });

  it('leaves head state INDETERMINATE — a later operation can still be dated at the basis', async () => {
    const identity = await buildIdentity();
    const { resolveIdentity } = clientFor(identity).callbacks();
    const head = await resolveIdentity(identity.did);
    expect(head?.basisDeterminate).toBeUndefined();
  });
});

// -----------------------------------------------------------------------------
// content chains are DAGs — head selection over a branch-inclusive log
// -----------------------------------------------------------------------------

const DOC_B = 'bafkreiforkeddocument0000000000000000000000000000000000000000';

const signUpdate = async (input: {
  signer: BuiltIdentity;
  previousOperationCID: string;
  createdAt: string;
  documentCID?: string;
  authorization?: string;
}) => {
  const operation = {
    version: 1 as const,
    type: 'update' as const,
    did: input.signer.did,
    previousOperationCID: input.previousOperationCID,
    documentCID: input.documentCID ?? DOC_B,
    baseDocumentCID: null,
    createdAt: input.createdAt,
    ...(input.authorization ? { authorization: input.authorization } : {}),
  };
  return signContentOperation({
    operation: operation as ContentOperation,
    signer: input.signer.k.signer,
    kid: input.signer.kid,
  });
};

describe('content DAG resolution', () => {
  const RELAY = 'https://relay.test';

  /** genesis (-8) → update (-4), plus a creator-signed sibling of the update (-3). */
  const forked = async () => {
    const creator = await buildIdentity();
    const content = await buildContent(creator, { update: true });
    const sibling = await signUpdate({
      signer: creator,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-3),
    });
    return { creator, content, sibling };
  };

  const clientOver = (data: Record<string, RelayData>, store = memoryStore()) =>
    createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data) });

  it('a forked log resolves to the tip with the highest createdAt', async () => {
    const { creator, content, sibling } = await forked();
    const client = clientOver({
      [RELAY]: {
        identities: { [creator.did]: creator.log },
        contents: { [content.contentId]: [...content.log, sibling.jwsToken] },
      },
    });
    const res = await client.content(content.contentId);
    expect(res.trust.ok).toBe(true);
    expect(res.value.chain.headCID).toBe(sibling.operationCID);
    expect(res.value.chain.length).toBe(2);
    expect(res.value.rejected).toEqual([]);
    // the raw floor still serves every branch
    expect((await client.log('content', content.contentId)).value).toHaveLength(3);
  });

  it('a cached chain that then forks resolves warm to the same head a cold read selects', async () => {
    const { creator, content, sibling } = await forked();
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log },
        contents: { [content.contentId]: [...content.log] },
      },
    };
    const client = clientOver(data);
    expect((await client.content(content.contentId)).value.chain.headCID).toBe(content.headCID);

    data[RELAY]!.contents![content.contentId] = [...content.log, sibling.jwsToken];
    const warm = await client.content(content.contentId);
    const cold = await clientOver(data).content(content.contentId);
    expect(warm.value.chain).toEqual(cold.value.chain);
    expect(warm.value.chain.headCID).toBe(sibling.operationCID);
    expect(warm.trust.unverifiable).toBeUndefined();
  });

  it('a branch set pinned from one relay and a different one from another resolve over the union', async () => {
    const { creator, content, sibling } = await forked();
    const OTHER = 'https://relay-b.test';
    const third = await signUpdate({
      signer: creator,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-5),
      documentCID: DOC_B.replace('forked', 'branchc'),
    });
    // R1 holds {G, A, B}; R2, unpeered, holds {G, A, C}
    const g = content.log[0]!;
    const A = content.log[1]!;
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log },
        contents: { [content.contentId]: [g, A, sibling.jwsToken] },
      },
      [OTHER]: {
        identities: { [creator.did]: creator.log },
        contents: { [content.contentId]: [g, A, third.jwsToken] },
      },
    };
    const store = memoryStore();
    await createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data) }).content(
      content.contentId,
    );
    const viaOther = createClient({ relays: [OTHER], store, peerClient: fakePeerClient(data) });
    const res = await viaOther.content(content.contentId);
    // head chosen over {G, A, B, C}: B is the latest tip
    expect(res.value.chain.headCID).toBe(sibling.operationCID);
    expect(res.trust.unverifiable).toBeUndefined(); // C is new
    const log = await viaOther.log('content', content.contentId);
    expect(log.value.map((op) => op.cid).sort()).toEqual(
      [content.genesisCID, content.headCID, sibling.operationCID, third.operationCID].sort(),
    );
  });
});

// -----------------------------------------------------------------------------
// credential authority on cached ops is re-asked on every read
// -----------------------------------------------------------------------------

describe('content authority recheck — warm agrees with cold', () => {
  const RELAY = 'https://relay.test';

  /** genesis by `creator` (-8), then an update by `delegate` (-4) under a
   *  creator-issued write credential. Revocations come from a mutable map. */
  const delegated = async () => {
    const creator = await buildIdentity();
    const delegate = await buildIdentity();
    const base = await buildContent(creator);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${base.contentId}`, action: 'write' }],
      exp: Math.floor(Date.now() / 1000) + 4 * 3600,
      iat: Math.floor(Date.now() / 1000) - 4 * 3600,
      signer: creator.k.signer,
      keyId: creator.k.keyId,
    });
    const opCreatedAt = ts(-4);
    const op = await signUpdate({
      signer: delegate,
      previousOperationCID: base.genesisCID,
      createdAt: opCreatedAt,
      authorization: credential,
    });
    const revokedAt = new Map<string, number>();
    const isRevoked: RevChecker = async (_issuer, credentialCID, asOfUnix) => {
      const at = revokedAt.get(credentialCID);
      if (at === undefined) return false;
      if (asOfUnix === undefined || asOfUnix <= 0) return true;
      return at <= asOfUnix;
    };
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: [...creator.log], [delegate.did]: delegate.log },
        contents: { [base.contentId]: [...base.log, op.jwsToken] },
      },
    };
    const clientFor = (store = memoryStore()) =>
      createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data), isRevoked });
    return {
      creator,
      contentId: base.contentId,
      genesisCID: base.genesisCID,
      op,
      credentialCID: cidOf(credential),
      opCreatedAtUnix: Math.floor(new Date(opCreatedAt).getTime() / 1000),
      revokedAt,
      data,
      clientFor,
    };
  };

  /** Delete the creator — the credential's issuer — on the relay. */
  const deleteCreator = async (c: Awaited<ReturnType<typeof delegated>>) => {
    const del = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'delete',
        previousOperationCID: c.creator.headCID,
        createdAt: ts(-1),
      },
      signer: c.creator.k.signer,
      keyId: c.creator.k.keyId,
      identityDID: c.creator.did,
    });
    c.data[RELAY]!.identities![c.creator.did] = [...c.creator.log, del.jwsToken];
  };

  const expectDropped = (
    res: Resolved<ResolvedContent>,
    c: Awaited<ReturnType<typeof delegated>>,
    reason: RegExp,
  ) => {
    expect(res.value.chain.length).toBe(1);
    expect(res.value.chain.headCID).toBe(c.genesisCID);
    expect(res.value.rejected).toEqual([
      { cid: c.op.operationCID, reason: expect.stringMatching(reason) },
    ]);
  };

  it('issuer deletion drops the delegated op on a warm read, exactly as on a cold read', async () => {
    const c = await delegated();
    const client = c.clientFor();
    expect((await client.content(c.contentId)).value.chain.length).toBe(2);

    await deleteCreator(c);
    const warm = await client.content(c.contentId);
    const cold = await c.clientFor().content(c.contentId);
    expectDropped(cold, c, /deleted/);
    expectDropped(warm, c, /deleted/);
    expect(warm.value.chain).toEqual(cold.value.chain);
    expect(warm.value.rejected).toEqual(cold.value.rejected);

    // the cache was rewritten from the cold result: a further warm read agrees
    const again = await client.content(c.contentId);
    expect(again.value.chain).toEqual(cold.value.chain);
    expect(again.value.rejected).toEqual(cold.value.rejected);
  });

  it('a revocation dated before the op drops it on a warm read, exactly as on a cold read', async () => {
    const c = await delegated();
    const client = c.clientFor();
    expect((await client.content(c.contentId)).value.chain.length).toBe(2);

    // arrives after the cache was written, but is dated before the op
    c.revokedAt.set(c.credentialCID, c.opCreatedAtUnix - 60);
    const warm = await client.content(c.contentId);
    const cold = await c.clientFor().content(c.contentId);
    expectDropped(cold, c, /revoked/);
    expectDropped(warm, c, /revoked/);
    expect(warm.value.chain).toEqual(cold.value.chain);
    expect(warm.value.rejected).toEqual(cold.value.rejected);
  });

  it('a revocation dated after the op still passes (revocation is not retroactive)', async () => {
    const c = await delegated();
    const client = c.clientFor();
    await client.content(c.contentId);

    c.revokedAt.set(c.credentialCID, c.opCreatedAtUnix + 60);
    const warm = await client.content(c.contentId);
    expect(warm.trust.ok).toBe(true);
    expect(warm.value.chain.length).toBe(2);
    expect(warm.value.chain.headCID).toBe(c.op.operationCID);
    expect(warm.value.rejected).toEqual([]);
    expect(warm.trust.unverifiable).toEqual(['tip', 'revocation']);
  });

  it('recheckContentAuthority answers from the cached lineage without draining the log', async () => {
    const c = await delegated();
    const client = c.clientFor();
    expect(await client.recheckContentAuthority(c.contentId)).toBeUndefined(); // nothing cached
    await client.content(c.contentId);
    expect(await client.recheckContentAuthority(c.contentId)).toEqual({
      opCount: 2,
      isDeleted: false,
      rejected: [],
    });

    c.revokedAt.set(c.credentialCID, c.opCreatedAtUnix + 60);
    // a later revocation leaves authority standing
    expect(await client.recheckContentAuthority(c.contentId)).toEqual({
      opCount: 2,
      isDeleted: false,
      rejected: [],
    });

    await deleteCreator(c);
    await expect(client.recheckContentAuthority(c.contentId)).rejects.toThrow(
      /authorization verification failed/,
    );
  });
});

// -----------------------------------------------------------------------------
// what the trusted log holds, and what a lookup failure is
// -----------------------------------------------------------------------------

describe('content DAG — trusted log, misses, conflicts, pin', () => {
  const RELAY = 'https://relay.test';

  const base = async () => {
    const creator = await buildIdentity();
    const stranger = await buildIdentity();
    const content = await buildContent(creator, { update: true });
    // a stranger's update with no credential: invalid, and dated last
    const bad = await signUpdate({
      signer: stranger,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-2),
    });
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log, [stranger.did]: stranger.log },
        contents: { [content.contentId]: [...content.log] },
      },
    };
    const store = memoryStore();
    const client = createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data) });
    const serve = (log: string[]) => {
      data[RELAY]!.contents![content.contentId] = log;
    };
    return { creator, stranger, content, bad, data, store, client, serve };
  };

  it('the trusted log carries only verified ops; a rejected op is listed apart', async () => {
    const { content, bad, store, client, serve } = await base();
    serve([...content.log, bad.jwsToken]);
    const res = await client.content(content.contentId);
    expect(res.value.rejected.map((r) => r.cid)).toEqual([bad.operationCID]);
    const log = await client.log('content', content.contentId);
    expect(log.value.map((op) => op.jwsToken)).toEqual(content.log);
    const row = (await store.get(`content:${content.contentId}`)) as { log: string[] };
    expect(row.log).toEqual(content.log);
  });

  it('an unresolvable signer identity fails the read as unverifiable, never an older head', async () => {
    const { creator, content, data, client, serve } = await base();
    const ghost = await buildIdentity(); // never served by the relay
    const op = await signUpdate({
      signer: ghost,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-2),
    });
    serve([...content.log, op.jwsToken]);
    expect(data[RELAY]!.identities![ghost.did]).toBeUndefined();
    const err = await client.content(content.contentId).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    expect(isDependencyMissing(err)).toBe(true);
    expect(divergenceErrorFrom(err)).toBeUndefined();
    void creator;
  });

  it('an unavailable revocation status fails the read as unverifiable, never an older head', async () => {
    const creator = await buildIdentity();
    const delegate = await buildIdentity();
    const content = await buildContent(creator);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${content.contentId}`, action: 'write' }],
      exp: Math.floor(Date.now() / 1000) + 4 * 3600,
      iat: Math.floor(Date.now() / 1000) - 4 * 3600,
      signer: creator.k.signer,
      keyId: creator.k.keyId,
    });
    const op = await signUpdate({
      signer: delegate,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-4),
      authorization: credential,
    });
    const client = createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({
        [RELAY]: {
          identities: { [creator.did]: creator.log, [delegate.did]: delegate.log },
          contents: { [content.contentId]: [...content.log, op.jwsToken] },
        },
      }),
      // the default checker, against a relay whose status route is down
      fetch: async () => new Response('', { status: 503 }),
    });
    const err = await client.content(content.contentId).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    expect(isDependencyMissing(err)).toBe(true);
  });

  it('one CID served with two different tokens is a hard error before any cached node is reused', async () => {
    const { creator, content, client, serve } = await base();
    await client.content(content.contentId); // caches g → u
    const decoded = decodeJwsUnsafe(content.log[1]!)!;
    // u's header CID over a different parent
    const other = await buildContent(creator);
    const forged = await createJws({
      header: { ...decoded.header, kid: creator.kid, cid: content.headCID },
      payload: { ...decoded.payload, previousOperationCID: other.genesisCID },
      sign: creator.k.signer,
    });
    for (const log of [
      [content.log[0]!, forged, content.log[1]!],
      [content.log[0]!, content.log[1]!, forged],
    ]) {
      serve(log);
      const err = await client.content(content.contentId).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(divergenceErrorFrom(err)).toBeUndefined();
      expect((err as Error).message).toMatch(
        /all candidate logs failed verification: .*conflicting operations under CID/,
      );
    }
  });

  it('only verified ops are pinned: a rejected op that later disappears is not a divergence', async () => {
    const { creator, content, bad, client, serve } = await base();
    serve([content.log[0]!, bad.jwsToken]);
    const first = await client.content(content.contentId);
    expect(first.value.rejected.map((r) => r.cid)).toEqual([bad.operationCID]);

    const next = await signUpdate({
      signer: creator,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-1),
      documentCID: DOC_B,
    });
    serve([content.log[0]!, next.jwsToken]);
    const second = await client.content(content.contentId);
    expect(second.value.chain.headCID).toBe(next.operationCID);
    expect(second.value.rejected).toEqual([]);
  });

  it('recheckContentAuthority reports the cached surviving count and rejections', async () => {
    const { content, bad, client, serve } = await base();
    expect(await client.recheckContentAuthority(content.contentId)).toBeUndefined();
    serve([...content.log, bad.jwsToken]);
    await client.content(content.contentId);
    expect(await client.recheckContentAuthority(content.contentId)).toEqual({
      opCount: 2,
      isDeleted: false,
      rejected: [{ cid: bad.operationCID, reason: expect.any(String) }],
    });
  });
});

// -----------------------------------------------------------------------------
// round 2: membership, the future bound, every branch rechecked, set quorum
// -----------------------------------------------------------------------------

describe('content DAG — membership, future bound, branch recheck, quorum', () => {
  const RELAY = 'https://relay.test';
  const OTHER = 'https://relay-b.test';

  const setup = async () => {
    const creator = await buildIdentity();
    const content = await buildContent(creator, { update: true });
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log },
        contents: { [content.contentId]: [...content.log] },
      },
    };
    const store = memoryStore();
    const client = createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data) });
    const serve = (log: string[]) => {
      data[RELAY]!.contents![content.contentId] = log;
    };
    return { creator, content, store, client, serve };
  };

  it('an orphan whose header CID is `constructor` is rejected, never in the trusted log', async () => {
    const { creator, content, client, serve } = await setup();
    await client.content(content.contentId); // seeds cached nodes too
    const orphan = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:content-op', kid: creator.kid, cid: 'constructor' },
      payload: { junk: true, previousOperationCID: 'bafy-elsewhere', createdAt: ts(-1) },
      sign: async () => new Uint8Array(64),
    });
    serve([...content.log, orphan]);
    for (const res of [
      await client.content(content.contentId),
      await createClient({
        relays: [RELAY],
        peerClient: fakePeerClient({
          [RELAY]: {
            identities: { [creator.did]: creator.log },
            contents: { [content.contentId]: [...content.log, orphan] },
          },
        }),
      }).content(content.contentId),
    ]) {
      expect(res.value.rejected.map((r) => r.cid)).toEqual(['constructor']);
      expect(res.value.chain.headCID).toBe(content.headCID);
    }
    const log = await client.log('content', content.contentId);
    expect(log.value.map((op) => op.cid)).not.toContain('constructor');
  });

  it('a correctly signed update dated 9999-01-01 never becomes the head', async () => {
    const { creator, content, client, serve } = await setup();
    const future = await signUpdate({
      signer: creator,
      previousOperationCID: content.headCID,
      createdAt: '9999-01-01T00:00:00.000Z',
    });
    serve([...content.log, future.jwsToken]);
    const res = await client.content(content.contentId);
    expect(res.value.chain.headCID).toBe(content.headCID);
    expect(res.value.rejected).toEqual([
      { cid: future.operationCID, reason: expect.stringMatching(/24 hours in the future/) },
    ]);
  });

  it('a backdated revocation on a losing delegated branch drops it warm exactly as cold', async () => {
    const creator = await buildIdentity();
    const delegate = await buildIdentity();
    const content = await buildContent(creator);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${content.contentId}`, action: 'write' }],
      exp: Math.floor(Date.now() / 1000) + 4 * 3600,
      iat: Math.floor(Date.now() / 1000) - 4 * 3600,
      signer: creator.k.signer,
      keyId: creator.k.keyId,
    });
    const opCreatedAt = ts(-4);
    const losing = await signUpdate({
      signer: delegate,
      previousOperationCID: content.genesisCID,
      createdAt: opCreatedAt,
      authorization: credential,
    });
    const winning = await signUpdate({
      signer: creator,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-3),
      documentCID: DOC_B,
    });
    const revokedAt = new Map<string, number>();
    const isRevoked: RevChecker = async (_issuer, credentialCID, asOfUnix) => {
      const at = revokedAt.get(credentialCID);
      if (at === undefined) return false;
      if (asOfUnix === undefined || asOfUnix <= 0) return true;
      return at <= asOfUnix;
    };
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log, [delegate.did]: delegate.log },
        contents: { [content.contentId]: [...content.log, losing.jwsToken, winning.jwsToken] },
      },
    };
    const clientFor = () =>
      createClient({
        relays: [RELAY],
        store: memoryStore(),
        peerClient: fakePeerClient(data),
        isRevoked,
      });
    const client = clientFor();
    const first = await client.content(content.contentId);
    expect(first.value.chain.headCID).toBe(winning.operationCID);
    expect((await client.log('content', content.contentId)).value).toHaveLength(3);

    revokedAt.set(cidOf(credential), Math.floor(new Date(opCreatedAt).getTime() / 1000) - 60);
    // the cached set still holds the losing op, and its authority is gone
    await expect(client.recheckContentAuthority(content.contentId)).rejects.toThrow(/revoked/);

    const warm = await client.content(content.contentId);
    const cold = await clientFor().content(content.contentId);
    const expectedRejected = [
      { cid: losing.operationCID, reason: expect.stringMatching(/revoked/) },
    ];
    for (const res of [warm, cold]) {
      expect(res.value.chain.headCID).toBe(winning.operationCID);
      expect(res.value.rejected).toEqual(expectedRejected);
    }
    expect(warm.value.chain).toEqual(cold.value.chain);
    const log = await client.log('content', content.contentId);
    expect(log.value.map((op) => op.cid)).toEqual([content.genesisCID, winning.operationCID]);
    expect(await client.recheckContentAuthority(content.contentId)).toEqual({
      opCount: 2,
      isDeleted: false,
      rejected: expectedRejected,
    });
  });

  it('quorum 2 agrees on a content log two relays serve in different orders', async () => {
    const creator = await buildIdentity();
    const content = await buildContent(creator);
    const a = await signUpdate({
      signer: creator,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-4),
    });
    const b = await signUpdate({
      signer: creator,
      previousOperationCID: content.genesisCID,
      createdAt: ts(-3),
      documentCID: DOC_B.replace('forked', 'branch'),
    });
    const g = content.log[0]!;
    const client = createClient({
      relays: [RELAY, OTHER],
      quorum: 2,
      peerClient: fakePeerClient({
        [RELAY]: {
          identities: { [creator.did]: creator.log },
          contents: { [content.contentId]: [g, a.jwsToken, b.jwsToken] },
        },
        [OTHER]: {
          identities: { [creator.did]: creator.log },
          contents: { [content.contentId]: [g, b.jwsToken, a.jwsToken] },
        },
      }),
    });
    const res = await client.content(content.contentId);
    expect(res.provenance.agreed).toBe(true);
    expect(res.value.chain.headCID).toBe(b.operationCID);
  });
});

// -----------------------------------------------------------------------------
// round 3: the cached rejected set, and the client's clock
// -----------------------------------------------------------------------------

describe('content DAG — cached rejected set identity, client clock', () => {
  const RELAY = 'https://relay.test';

  it('a rejected op replaced by another rejected op, then a subset answer, resolves from the union', async () => {
    const creator = await buildIdentity();
    const stranger = await buildIdentity();
    const content = await buildContent(creator, { update: true });
    const reject = (createdAt: string, documentCID: string) =>
      signUpdate({
        signer: stranger,
        previousOperationCID: content.genesisCID,
        createdAt,
        documentCID,
      });
    const A = await reject(ts(-2), DOC_B);
    const B = await reject(ts(-1), DOC_B.replace('forked', 'second'));
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log, [stranger.did]: stranger.log },
        contents: { [content.contentId]: [...content.log, A.jwsToken] },
      },
    };
    const client = createClient({
      relays: [RELAY],
      store: memoryStore(),
      peerClient: fakePeerClient(data),
    });
    expect((await client.content(content.contentId)).value.rejected.map((r) => r.cid)).toEqual([
      A.operationCID,
    ]);
    data[RELAY]!.contents![content.contentId] = [...content.log, B.jwsToken];
    expect((await client.content(content.contentId)).value.rejected.map((r) => r.cid)).toEqual([
      B.operationCID,
    ]);
    // u missing, B already seen (rejected): a relay behind, not a contradiction
    data[RELAY]!.contents![content.contentId] = [content.log[0]!, B.jwsToken];
    const third = await client.content(content.contentId).then(
      (res) => res,
      (e: unknown) => e,
    );
    expect(divergenceErrorFrom(third)).toBeUndefined();
    expect(third).not.toBeInstanceOf(Error);
    // u is still in the union, so the head stands
    expect((third as Resolved<ResolvedContent>).value.chain.headCID).toBe(content.headCID);
    expect((third as Resolved<ResolvedContent>).trust.unverifiable).toEqual(['tip']);
  });

  it('the future bound runs on the client clock: a 2040 clock accepts a genesis dated just before 2040', async () => {
    const creator = await buildIdentity();
    const g = await signContentOperation({
      operation: {
        version: 1,
        type: 'create',
        did: creator.did,
        documentCID: DOC_B,
        baseDocumentCID: null,
        createdAt: '2039-12-31T12:00:00.000Z',
      },
      signer: creator.k.signer,
      kid: creator.kid,
    });
    const genesisOnly = await verifyContentDag({
      log: [g.jwsToken],
      resolveKey: async () => decodeMultikey(creator.k.key.publicKeyMultibase).keyBytes,
      now: () => Date.parse('2040-01-01T00:00:00.000Z'),
    });
    const contentId = genesisOnly.head.contentId;
    const clientAt = (now?: () => number) =>
      createClient({
        relays: [RELAY],
        ...(now ? { now } : {}),
        peerClient: fakePeerClient({
          [RELAY]: {
            identities: { [creator.did]: creator.log },
            contents: { [contentId]: [g.jwsToken] },
          },
        }),
      });
    const res = await clientAt(() => Date.parse('2040-01-01T00:00:00.000Z')).content(contentId);
    expect(res.value.chain.headCID).toBe(g.operationCID);
    // the host clock (2026) still refuses it
    await expect(clientAt().content(contentId)).rejects.toThrow(/24 hours in the future/);
  });
});

// -----------------------------------------------------------------------------
// round 4: the monotone union — authority first, prunes, malformed tokens,
// and the offline fallback
// -----------------------------------------------------------------------------

describe('content union — authority first, prunes, malformed tokens, offline', () => {
  const RELAY = 'https://relay.test';

  /** G (creator) → D (delegate, under a credential, -4), plus W (creator, -3)
   *  off G when `winner` is set. Revocations come from a mutable map. */
  const setup = async (opts?: { winner?: boolean }) => {
    const creator = await buildIdentity();
    const delegate = await buildIdentity();
    const content = await buildContent(creator);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${content.contentId}`, action: 'write' }],
      exp: Math.floor(Date.now() / 1000) + 4 * 3600,
      iat: Math.floor(Date.now() / 1000) - 4 * 3600,
      signer: creator.k.signer,
      keyId: creator.k.keyId,
    });
    const dAt = ts(-4);
    const D = await signUpdate({
      signer: delegate,
      previousOperationCID: content.genesisCID,
      createdAt: dAt,
      authorization: credential,
    });
    const W = opts?.winner
      ? await signUpdate({
          signer: creator,
          previousOperationCID: content.genesisCID,
          createdAt: ts(-3),
          documentCID: DOC_B,
        })
      : undefined;
    const revokedAt = new Map<string, number>();
    const isRevoked: RevChecker = async (_issuer, credentialCID, asOfUnix) => {
      const at = revokedAt.get(credentialCID);
      if (at === undefined) return false;
      if (asOfUnix === undefined || asOfUnix <= 0) return true;
      return at <= asOfUnix;
    };
    const data: Record<string, RelayData> = {
      [RELAY]: {
        identities: { [creator.did]: creator.log, [delegate.did]: delegate.log },
        contents: {
          [content.contentId]: [...content.log, D.jwsToken, ...(W ? [W.jwsToken] : [])],
        },
      },
    };
    const clientFor = (store = memoryStore()) =>
      createClient({ relays: [RELAY], store, peerClient: fakePeerClient(data), isRevoked });
    const revokeBeforeD = () =>
      revokedAt.set(cidOf(credential), Math.floor(new Date(dAt).getTime() / 1000) - 60);
    return { creator, content, D, W, data, clientFor, revokeBeforeD };
  };

  it('a revoked cached parent with an unresolvable new descendant: warm equals cold', async () => {
    const c = await setup();
    const client = c.clientFor();
    expect((await client.content(c.content.contentId)).value.chain.headCID).toBe(c.D.operationCID);
    c.revokeBeforeD();
    const ghost = await buildIdentity(); // no relay holds it
    const X = await signUpdate({
      signer: ghost,
      previousOperationCID: c.D.operationCID,
      createdAt: ts(-2),
    });
    c.data[RELAY]!.contents![c.content.contentId]!.push(X.jwsToken);

    const warm = await client.content(c.content.contentId);
    const cold = await c.clientFor().content(c.content.contentId);
    expect(warm.value.chain).toEqual(cold.value.chain);
    expect(warm.value.chain.headCID).toBe(c.content.genesisCID);
    const cids = (r: typeof warm) => r.value.rejected.map((x) => x.cid).sort();
    expect(cids(warm)).toEqual([c.D.operationCID, X.operationCID].sort());
    expect(cids(warm)).toEqual(cids(cold));
  });

  it('a prune that shrinks the set with no new op leaves the tip unverified', async () => {
    const c = await setup({ winner: true });
    const client = c.clientFor();
    await client.content(c.content.contentId);
    c.revokeBeforeD();
    const res = await client.content(c.content.contentId);
    expect(res.value.chain.headCID).toBe(c.W!.operationCID);
    expect(res.value.rejected.map((r) => r.cid)).toEqual([c.D.operationCID]);
    expect(res.trust.unverifiable).toContain('tip');
  });

  it('two malformed tokens are rejected one by one; the candidate still resolves', async () => {
    const c = await setup();
    c.data[RELAY]!.contents![c.content.contentId]!.push('not-a-jws', 'also.not-a.jws');
    const res = await c.clientFor().content(c.content.contentId);
    expect(res.value.chain.headCID).toBe(c.D.operationCID);
    expect(res.value.rejected).toHaveLength(2);
    expect(res.value.rejected.every((r) => r.cid === '')).toBe(true);
  });

  it('offline, a withdrawn cached op is not returned as trusted', async () => {
    const c = await setup();
    const client = c.clientFor();
    await client.content(c.content.contentId);
    c.revokeBeforeD();
    delete c.data[RELAY]!.contents; // no relay answers for the content log
    const res = await client.content(c.content.contentId);
    expect(res.provenance.fromCache).toBe(true);
    expect(res.trust.unverifiable).toContain('tip');
    expect(res.value.chain.headCID).toBe(c.content.genesisCID);
    expect(res.value.rejected.map((r) => r.cid)).toEqual([c.D.operationCID]);
    const log = await client.log('content', c.content.contentId);
    expect(log.value.map((op) => op.cid)).toEqual([c.content.genesisCID]);
  });

  it('offline, an authority check that cannot be made keeps the cached answer', async () => {
    const c = await setup();
    let down = false;
    const store = memoryStore();
    const client = createClient({
      relays: [RELAY],
      store,
      peerClient: fakePeerClient(c.data),
      isRevoked: async () => {
        if (down) throw new Error('revocation status unavailable: no relay answered');
        return false;
      },
    });
    await client.content(c.content.contentId);
    down = true;
    delete c.data[RELAY]!.contents;
    const res = await client.content(c.content.contentId);
    expect(res.provenance.fromCache).toBe(true);
    expect(res.value.chain.headCID).toBe(c.D.operationCID);
  });
});
