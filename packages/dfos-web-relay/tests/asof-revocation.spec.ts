import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  signRevocation,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createDFOSCredential,
  decodeDFOSCredentialUnsafe,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { ingestOperations } from '../src/ingest';
import { MemoryRelayStore } from '../src/store';

/*

  AS-OF REVOCATION AT THE RELAY

  Two decisions, deliberately split:

  - ACCEPTANCE (ingest) is a FRESHNESS decision. A relay must not admit a NEW
    operation authorized by a credential it already knows to be revoked — no
    matter how the operation is dated. Net behavior here is UNCHANGED by the
    as-of work, and the backdating test below is the guard that ingest did not
    quietly adopt as-of semantics (which would let a revoked delegate keep
    writing simply by backdating).
  - VALIDITY (historical replay via getContentStateAtCID) is an AS-OF decision.
    A credential revoked AFTER an operation was committed leaves that operation
    valid, so the fork-point state it contributes to stays computable.

  Twin coverage lives in the Go relay (asof_revocation_test.go).

*/

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

/** ISO timestamp `offset` minutes from now (negative = backdated). */
const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();
const nowUnix = () => Math.floor(Date.now() / 1000);

const createIdentity = async () => {
  const controller = makeKey();
  const authKey = makeKey();
  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [authKey.key],
    assertKeys: [],
    controllerKeys: [controller.key],
    createdAt: ts(-60),
  };
  const { jwsToken } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, controller, authKey, jwsToken };
};

const newDoc = async (title: string) => {
  const enc = await dagCborCanonicalEncode({ type: 'post', title } as unknown as Record<
    string,
    unknown
  >);
  return enc.cid.toString();
};

const genesisOp = async (identity: Awaited<ReturnType<typeof createIdentity>>, offset: number) => {
  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID: await newDoc('genesis'),
    baseDocumentCID: null,
    createdAt: ts(offset),
    note: null,
  };
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op,
    signer: identity.authKey.signer,
    kid: `${identity.did}#${identity.authKey.keyId}`,
  });
  return { jwsToken, operationCID };
};

/** An update op, optionally delegated (carrying an inline authorization). */
const updateOp = async (
  signerIdentity: Awaited<ReturnType<typeof createIdentity>>,
  previousCID: string,
  title: string,
  offset: number,
  authorization?: string,
) => {
  const op = {
    version: 1 as const,
    type: 'update' as const,
    did: signerIdentity.did,
    previousOperationCID: previousCID,
    documentCID: await newDoc(title),
    baseDocumentCID: null,
    createdAt: ts(offset),
    note: null,
    ...(authorization ? { authorization } : {}),
  };
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op as unknown as ContentOperation,
    signer: signerIdentity.authKey.signer,
    kid: `${signerIdentity.did}#${signerIdentity.authKey.keyId}`,
  });
  return { jwsToken, operationCID };
};

/**
 * Seed a store with creator + delegate identities, a genesis content chain, and a
 * write credential from creator to delegate. Credential iat is well backdated so
 * ops dated in the recent past are still inside [iat, exp).
 */
const seedChain = async (genesisOffset: number) => {
  const store = new MemoryRelayStore();
  const creator = await createIdentity();
  const delegate = await createIdentity();
  const genesis = await genesisOp(creator, genesisOffset);
  await ingestOperations([creator.jwsToken, delegate.jwsToken, genesis.jwsToken], store);
  const [seeded] = await ingestOperations([genesis.jwsToken], store);
  const contentId = seeded!.chainId!;

  const credential = await createDFOSCredential({
    issuerDID: creator.did,
    audienceDID: delegate.did,
    att: [{ resource: `chain:${contentId}`, action: 'write' }],
    exp: nowUnix() + 3600,
    signer: creator.authKey.signer,
    keyId: creator.authKey.keyId,
    iat: nowUnix() - 3600,
  });
  const credentialCID = decodeDFOSCredentialUnsafe(credential)!.header.cid;

  const revoke = async () => {
    const { jwsToken } = await signRevocation({
      issuerDID: creator.did,
      credentialCID,
      signer: creator.authKey.signer,
      keyId: creator.authKey.keyId,
    });
    const [res] = await ingestOperations([jwsToken], store);
    expect(res!.status).toBe('new');
  };

  return { store, creator, delegate, genesis, contentId, credential, credentialCID, revoke };
};

// -----------------------------------------------------------------------------
// store: the as-of compare
// -----------------------------------------------------------------------------

describe('relay store — as-of revocation', () => {
  it('persists the revocation createdAt and answers both questions from it', async () => {
    const c = await seedChain(-30);
    await c.revoke();

    const stored = await c.store.getRevocationForCredential(c.credentialCID);
    expect(stored?.createdAt).toBeTruthy();
    const revokedAtUnix = Math.floor(new Date(stored!.createdAt).getTime() / 1000);

    // timeless — the freshness question: revoked, full stop
    expect(await c.store.isCredentialRevoked(c.creator.did, c.credentialCID)).toBe(true);

    // as-of BEFORE the revocation — not yet revoked at that instant
    expect(
      await c.store.isCredentialRevoked(c.creator.did, c.credentialCID, revokedAtUnix - 60),
    ).toBe(false);

    // as-of AT the revocation — inclusive boundary
    expect(await c.store.isCredentialRevoked(c.creator.did, c.credentialCID, revokedAtUnix)).toBe(
      true,
    );

    // as-of AFTER the revocation
    expect(
      await c.store.isCredentialRevoked(c.creator.did, c.credentialCID, revokedAtUnix + 60),
    ).toBe(true);
  });

  it('reports an unknown credential as not revoked on both bases', async () => {
    const c = await seedChain(-30);
    expect(await c.store.isCredentialRevoked(c.creator.did, c.credentialCID)).toBe(false);
    expect(await c.store.isCredentialRevoked(c.creator.did, c.credentialCID, nowUnix())).toBe(
      false,
    );
  });
});

// -----------------------------------------------------------------------------
// ingest: freshness is unchanged
// -----------------------------------------------------------------------------

describe('relay ingest — acceptance stays a freshness decision', () => {
  it('SECURITY: still rejects a new delegated write under a currently-revoked credential', async () => {
    const c = await seedChain(-30);
    const w1 = await updateOp(c.delegate, c.genesis.operationCID, 'first', -20, c.credential);
    expect((await ingestOperations([w1.jwsToken], c.store))[0]!.status).toBe('new');

    await c.revoke();

    const w2 = await updateOp(c.delegate, w1.operationCID, 'second', -10, c.credential);
    const [res] = await ingestOperations([w2.jwsToken], c.store);
    expect(res!.status).toBe('rejected');
    expect(res!.error).toMatch(/revoked/);
  });

  it('SECURITY: rejects a BACKDATED delegated write under a currently-revoked credential', async () => {
    // The guard that ingest did NOT adopt as-of semantics. This op is dated BEFORE
    // the revocation, so an as-of check would call the credential live and admit
    // it — handing a revoked delegate an indefinite write window just by choosing
    // an older createdAt. Acceptance asks what the relay knows NOW, so it rejects.
    const c = await seedChain(-30);
    const w1 = await updateOp(c.delegate, c.genesis.operationCID, 'first', -25, c.credential);
    expect((await ingestOperations([w1.jwsToken], c.store))[0]!.status).toBe('new');

    await c.revoke();

    // dated 20 minutes ago — comfortably before the revocation just ingested
    const backdated = await updateOp(c.delegate, w1.operationCID, 'backdated', -20, c.credential);
    const [res] = await ingestOperations([backdated.jwsToken], c.store);
    expect(res!.status).toBe('rejected');
    expect(res!.error).toMatch(/revoked/);
  });
});

// -----------------------------------------------------------------------------
// getContentStateAtCID: historical replay is a validity decision
// -----------------------------------------------------------------------------

describe('getContentStateAtCID — historical replay', () => {
  it('replays a delegated op whose credential was revoked AFTER it', async () => {
    const c = await seedChain(-30);
    // delegated op A, then a creator-signed head B, so A sits mid-chain
    const a = await updateOp(c.delegate, c.genesis.operationCID, 'A', -25, c.credential);
    expect((await ingestOperations([a.jwsToken], c.store))[0]!.status).toBe('new');
    const b = await updateOp(c.creator, a.operationCID, 'B', -20);
    expect((await ingestOperations([b.jwsToken], c.store))[0]!.status).toBe('new');

    // revoked NOW — after both committed ops
    await c.revoke();

    const state = await c.store.getContentStateAtCID(c.contentId, a.operationCID);
    expect(state).not.toBeNull();
    expect(state!.state.length).toBe(2);
  });

  it('lets a fork extend from a state whose credential is now revoked', async () => {
    // The user-visible payoff: a legitimate fork off a historical op must stay
    // acceptable after the credential behind that op is revoked. The fork op is
    // creator-signed, so ingest's own freshness gate is not what is under test —
    // only whether the fork-point state still computes.
    const c = await seedChain(-30);
    const a = await updateOp(c.delegate, c.genesis.operationCID, 'A', -25, c.credential);
    await ingestOperations([a.jwsToken], c.store);
    const b = await updateOp(c.creator, a.operationCID, 'B', -20);
    await ingestOperations([b.jwsToken], c.store);

    await c.revoke();

    const fork = await updateOp(c.creator, a.operationCID, 'fork', -22);
    const [res] = await ingestOperations([fork.jwsToken], c.store);
    expect(res!.status).toBe('new');
  });

  it('REJECTS a replay whose delegated op postdates the revocation', async () => {
    // Mirror image: op A is dated AFTER the revocation, so as of its own createdAt
    // the credential was already dead and the historical state does not verify.
    // (A was admitted at ingest only because the revocation had not arrived yet —
    // exactly the divergence a later fold is supposed to resolve.)
    const c = await seedChain(-30);
    const a = await updateOp(c.delegate, c.genesis.operationCID, 'A', 5, c.credential);
    expect((await ingestOperations([a.jwsToken], c.store))[0]!.status).toBe('new');

    // revoked NOW — before A's own (future-dated) createdAt
    await c.revoke();

    await expect(c.store.getContentStateAtCID(c.contentId, a.operationCID)).rejects.toThrow(
      /revoked/,
    );
  });
});
