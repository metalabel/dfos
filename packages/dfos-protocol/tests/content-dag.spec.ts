import { describe, expect, it } from 'vitest';
import {
  encodeEd25519Multikey,
  recheckContentAuthorization,
  signContentOperation,
  verifyContentChain,
  verifyContentDag,
} from '../src/chain';
import type { ContentOperation, VerifiedIdentity } from '../src/chain';
import { createDFOSCredential, decodeDFOSCredentialUnsafe } from '../src/credentials';
import type { RevocationChecker } from '../src/credentials';
import {
  createJws,
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';
import { isDependencyMissing, markDependencyMissing } from '../src/dependency';

/*

  CONTENT DAG — head selection over a branch-inclusive log, and the authority
  recheck a cached lineage runs on every read.

*/

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    authKeys: [
      { id: keyId, type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey) },
    ],
    assertKeys: [],
    controllerKeys: [],
    services: [],
  };
  return { keypair, keyId, did, kid, signer, identity };
};
type Identity = ReturnType<typeof makeIdentity>;

const ts = (offsetMinutes = 0) => new Date(Date.now() + offsetMinutes * 60_000).toISOString();
const unix = (offsetMinutes = 0) => Math.floor(Date.now() / 1000) + offsetMinutes * 60;
const docCID = async (title: string) =>
  (await dagCborCanonicalEncode({ type: 'post', title })).cid.toString();

const asOfChecker = (revoked: Map<string, number>): RevocationChecker => {
  return async (issuerDID, credentialCID, asOfUnix) => {
    const revokedAt = revoked.get(`${issuerDID}::${credentialCID}`);
    if (revokedAt === undefined) return false;
    if (asOfUnix === undefined) return true;
    return revokedAt <= asOfUnix;
  };
};

const world = (...ids: Identity[]) => {
  const keys = new Map<string, Uint8Array>();
  const identities = new Map<string, VerifiedIdentity>();
  for (const id of ids) {
    keys.set(id.kid, id.keypair.publicKey);
    identities.set(id.did, id.identity);
  }
  let keyCalls = 0;
  const resolveKey = async (kid: string) => {
    keyCalls += 1;
    const key = keys.get(kid);
    if (!key) throw new Error(`unknown kid: ${kid}`);
    return key;
  };
  const resolveIdentity = async (did: string) => identities.get(did);
  return { identities, resolveKey, resolveIdentity, keyCalls: () => keyCalls };
};

const genesisOp = async (creator: Identity, createdAt: string) => {
  const operation: ContentOperation = {
    version: 1,
    type: 'create',
    did: creator.did,
    documentCID: await docCID('genesis'),
    baseDocumentCID: null,
    createdAt,
  };
  return signContentOperation({ operation, signer: creator.signer, kid: creator.kid });
};

const updateOp = async (input: {
  signer: Identity;
  previousOperationCID: string;
  createdAt: string;
  title: string;
  authorization?: string;
}) => {
  const operation: ContentOperation = {
    version: 1,
    type: 'update',
    did: input.signer.did,
    previousOperationCID: input.previousOperationCID,
    documentCID: await docCID(input.title),
    baseDocumentCID: null,
    createdAt: input.createdAt,
    ...(input.authorization ? { authorization: input.authorization } : {}),
  };
  return signContentOperation({ operation, signer: input.signer.signer, kid: input.signer.kid });
};

const cidOfToken = (jws: string): string =>
  JSON.parse(Buffer.from(jws.split('.')[0]!, 'base64url').toString('utf8')).cid;

// -----------------------------------------------------------------------------
// verifyContentDag
// -----------------------------------------------------------------------------

describe('verifyContentDag — head selection', () => {
  it('a fork picks the tip with the highest createdAt', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(2),
      title: 'a',
    });
    const b = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'b',
    });

    // log order must not matter
    for (const log of [
      [g.jwsToken, a.jwsToken, b.jwsToken],
      [g.jwsToken, b.jwsToken, a.jwsToken],
    ]) {
      const dag = await verifyContentDag({ log, resolveKey: w.resolveKey });
      expect(dag.head.headCID).toBe(a.operationCID);
      expect(dag.head.length).toBe(2);
      expect(dag.headLineage).toEqual([g.jwsToken, a.jwsToken]);
      expect(dag.tips.map((t) => t.cid)).toEqual([a.operationCID, b.operationCID]);
      expect(dag.rejected).toEqual([]);
    }
  });

  it('a createdAt tie picks the tip with the highest CID', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const at = ts(1);
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: at,
      title: 'a',
    });
    const b = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: at,
      title: 'b',
    });
    const winner = a.operationCID > b.operationCID ? a : b;

    const dag = await verifyContentDag({
      log: [g.jwsToken, a.jwsToken, b.jwsToken],
      resolveKey: w.resolveKey,
    });
    expect(dag.head.headCID).toBe(winner.operationCID);
    expect(dag.headLineage).toEqual([g.jwsToken, winner.jwsToken]);
  });

  it('the head may sit deeper on one branch than the other branch reaches', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a1 = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a1',
    });
    const a2 = await updateOp({
      signer: creator,
      previousOperationCID: a1.operationCID,
      createdAt: ts(3),
      title: 'a2',
    });
    const b1 = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(2),
      title: 'b1',
    });

    const dag = await verifyContentDag({
      log: [g.jwsToken, a1.jwsToken, b1.jwsToken, a2.jwsToken],
      resolveKey: w.resolveKey,
    });
    expect(dag.head.headCID).toBe(a2.operationCID);
    expect(dag.head.length).toBe(3);
    expect(dag.headLineage).toEqual([g.jwsToken, a1.jwsToken, a2.jwsToken]);
    expect(Object.keys(dag.nodes).sort()).toEqual(
      [g.operationCID, a1.operationCID, a2.operationCID, b1.operationCID].sort(),
    );
  });
});

describe('verifyContentDag — rejection', () => {
  it('an invalid sibling is dropped together with its subtree', async () => {
    const creator = makeIdentity();
    const stranger = makeIdentity();
    const w = world(creator, stranger);
    const g = await genesisOp(creator, ts(0));
    const good = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'good',
    });
    // a stranger with no credential, dated later so it would otherwise win
    const bad = await updateOp({
      signer: stranger,
      previousOperationCID: g.operationCID,
      createdAt: ts(2),
      title: 'bad',
    });
    const badChild = await updateOp({
      signer: creator,
      previousOperationCID: bad.operationCID,
      createdAt: ts(3),
      title: 'bad child',
    });

    const dag = await verifyContentDag({
      log: [g.jwsToken, good.jwsToken, bad.jwsToken, badChild.jwsToken],
      resolveKey: w.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: w.resolveIdentity,
    });
    expect(dag.head.headCID).toBe(good.operationCID);
    expect(dag.tips.map((t) => t.cid)).toEqual([good.operationCID]);
    expect(dag.rejected.map((r) => r.cid).sort()).toEqual(
      [bad.operationCID, badChild.operationCID].sort(),
    );
    expect(dag.rejected.find((r) => r.cid === bad.operationCID)!.reason).toMatch(
      /authorization credential required/,
    );
    expect(dag.nodes[badChild.operationCID]).toBeUndefined();
  });

  it('one CID served with two different tokens is a hard error, whatever the order', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const other = await genesisOp(creator, ts(-1));
    const u = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'u',
    });
    // u's header CID over a different payload (a different parent)
    const forged = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:content-op', kid: creator.kid, cid: u.operationCID },
      payload: {
        version: 1,
        type: 'update',
        did: creator.did,
        previousOperationCID: other.operationCID,
        documentCID: await docCID('forged'),
        baseDocumentCID: null,
        createdAt: ts(1),
      },
      sign: creator.signer,
    });
    for (const log of [
      [g.jwsToken, forged, u.jwsToken],
      [g.jwsToken, u.jwsToken, forged],
    ]) {
      await expect(verifyContentDag({ log, resolveKey: w.resolveKey })).rejects.toThrow(
        /conflicting operations under CID/,
      );
    }
  });

  it('two genesis operations are a hard error', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g1 = await genesisOp(creator, ts(0));
    const g2 = await genesisOp(creator, ts(1));
    await expect(
      verifyContentDag({ log: [g1.jwsToken, g2.jwsToken], resolveKey: w.resolveKey }),
    ).rejects.toThrow(/more than one genesis/);
  });

  it('a log with no genesis is a hard error', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a',
    });
    await expect(verifyContentDag({ log: [a.jwsToken], resolveKey: w.resolveKey })).rejects.toThrow(
      /no genesis/,
    );
  });

  it('an operation whose parent is absent from the log is rejected', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a',
    });
    const b = await updateOp({
      signer: creator,
      previousOperationCID: a.operationCID,
      createdAt: ts(2),
      title: 'b',
    });
    const dag = await verifyContentDag({
      log: [g.jwsToken, b.jwsToken],
      resolveKey: w.resolveKey,
    });
    expect(dag.head.headCID).toBe(g.operationCID);
    expect(dag.rejected).toEqual([
      { cid: b.operationCID, reason: 'previous operation is not in the log' },
    ]);
  });

  it('a dependency miss is rethrown, not dropped', async () => {
    const creator = makeIdentity();
    const other = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: other,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a',
    });
    const resolveKey = async (kid: string) => {
      if (kid === other.kid) throw markDependencyMissing(new Error(`unknown identity: ${kid}`));
      return w.resolveKey(kid);
    };
    const err = await verifyContentDag({ log: [g.jwsToken, a.jwsToken], resolveKey }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(Error);
    expect(isDependencyMissing(err)).toBe(true);
  });

  it('known nodes are not re-verified', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a',
    });
    const first = await verifyContentDag({
      log: [g.jwsToken, a.jwsToken],
      resolveKey: w.resolveKey,
    });
    const before = w.keyCalls();
    const b = await updateOp({
      signer: creator,
      previousOperationCID: a.operationCID,
      createdAt: ts(2),
      title: 'b',
    });
    const second = await verifyContentDag({
      log: [g.jwsToken, a.jwsToken, b.jwsToken],
      resolveKey: w.resolveKey,
      known: first.nodes,
    });
    expect(w.keyCalls() - before).toBe(1);
    expect(second.head.headCID).toBe(b.operationCID);
    expect(second.head.length).toBe(3);
  });

  it('a linear log folds to the same state verifyContentChain computes', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a',
    });
    const log = [g.jwsToken, a.jwsToken];
    const dag = await verifyContentDag({ log, resolveKey: w.resolveKey });
    expect(dag.head).toEqual(await verifyContentChain({ log, resolveKey: w.resolveKey }));
    expect(cidOfToken(dag.headLineage[1]!)).toBe(a.operationCID);
  });
});

// -----------------------------------------------------------------------------
// recheckContentAuthorization
// -----------------------------------------------------------------------------

describe('recheckContentAuthorization', () => {
  /** Genesis by `creator`, then an update by `delegate` under a creator-issued
   *  write credential, dated +1 minute. */
  const delegated = async () => {
    const creator = makeIdentity();
    const delegate = makeIdentity();
    const w = world(creator, delegate);
    const g = await genesisOp(creator, ts(0));
    const genesis = await verifyContentChain({ log: [g.jwsToken], resolveKey: w.resolveKey });
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${genesis.contentId}`, action: 'write' }],
      exp: unix(240),
      signer: creator.signer,
      keyId: creator.keyId,
      iat: unix(-240),
    });
    const opCreatedAt = ts(1);
    const u = await updateOp({
      signer: delegate,
      previousOperationCID: g.operationCID,
      createdAt: opCreatedAt,
      title: 'delegated',
      authorization: credential,
    });
    return {
      creator,
      w,
      log: [g.jwsToken, u.jwsToken],
      contentId: genesis.contentId,
      opCreatedAtUnix: Math.floor(new Date(opCreatedAt).getTime() / 1000),
      leafKey: `${creator.did}::${decodeDFOSCredentialUnsafe(credential)!.header.cid}`,
    };
  };

  it('passes while the credential holds', async () => {
    const c = await delegated();
    await expect(
      recheckContentAuthorization({
        log: c.log,
        creatorDID: c.creator.did,
        contentId: c.contentId,
        resolveIdentity: c.w.resolveIdentity,
        isRevoked: asOfChecker(new Map()),
      }),
    ).resolves.toBeUndefined();
  });

  it('fails once the credential issuer is deleted (deletion is retroactive)', async () => {
    const c = await delegated();
    c.w.identities.set(c.creator.did, { ...c.creator.identity, isDeleted: true });
    await expect(
      recheckContentAuthorization({
        log: c.log,
        creatorDID: c.creator.did,
        contentId: c.contentId,
        resolveIdentity: c.w.resolveIdentity,
      }),
    ).rejects.toThrow(/log\[1\]: authorization verification failed/);
  });

  it('fails on a revocation dated before the op (backdated revocation bites)', async () => {
    const c = await delegated();
    await expect(
      recheckContentAuthorization({
        log: c.log,
        creatorDID: c.creator.did,
        contentId: c.contentId,
        resolveIdentity: c.w.resolveIdentity,
        isRevoked: asOfChecker(new Map([[c.leafKey, unix(-10)]])),
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('fails on a revocation dated exactly at the op createdAt', async () => {
    const c = await delegated();
    await expect(
      recheckContentAuthorization({
        log: c.log,
        creatorDID: c.creator.did,
        contentId: c.contentId,
        resolveIdentity: c.w.resolveIdentity,
        isRevoked: asOfChecker(new Map([[c.leafKey, c.opCreatedAtUnix]])),
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('passes on a revocation dated after the op (revocation is not retroactive)', async () => {
    const c = await delegated();
    await expect(
      recheckContentAuthorization({
        log: c.log,
        creatorDID: c.creator.did,
        contentId: c.contentId,
        resolveIdentity: c.w.resolveIdentity,
        isRevoked: asOfChecker(new Map([[c.leafKey, unix(10)]])),
      }),
    ).resolves.toBeUndefined();
  });

  it('carries the dependency marker when the issuer cannot be resolved', async () => {
    const c = await delegated();
    const err = await recheckContentAuthorization({
      log: c.log,
      creatorDID: c.creator.did,
      contentId: c.contentId,
      resolveIdentity: async () => undefined,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(isDependencyMissing(err)).toBe(true);
  });

  it('creator-signed ops need no credential', async () => {
    const creator = makeIdentity();
    const w = world(creator);
    const g = await genesisOp(creator, ts(0));
    const a = await updateOp({
      signer: creator,
      previousOperationCID: g.operationCID,
      createdAt: ts(1),
      title: 'a',
    });
    const state = await verifyContentChain({
      log: [g.jwsToken, a.jwsToken],
      resolveKey: w.resolveKey,
    });
    await expect(
      recheckContentAuthorization({
        log: [g.jwsToken, a.jwsToken],
        creatorDID: creator.did,
        contentId: state.contentId,
        resolveIdentity: async () => undefined,
      }),
    ).resolves.toBeUndefined();
  });
});
