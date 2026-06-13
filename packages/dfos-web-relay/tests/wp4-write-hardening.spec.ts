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

  WP-4 — credential WRITE-path hardening (TS twin)

  The headline is the LEAF-revocation check on the write path:
  verifyDelegationChain only checks PARENTS, so without an explicit leaf check a
  revoked LEAF credential would still authorize writes. These tests drive a
  DELEGATED content write (an op signed by a non-creator, carrying an inline
  `authorization` credential) and assert that revoking the leaf blocks the next
  write, plus the aud:'*'-inline and read,write-action cases that lock parity
  with the Go twin.

*/

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

const createIdentity = async () => {
  const controller = makeKey();
  const authKey = makeKey();
  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [authKey.key],
    assertKeys: [],
    controllerKeys: [controller.key],
    createdAt: ts(),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, controller, authKey, jwsToken, operationCID };
};

const createContentOp = async (identity: Awaited<ReturnType<typeof createIdentity>>) => {
  const document = { type: 'post', title: 'hello', body: 'world' };
  const docEncoded = await dagCborCanonicalEncode(document as unknown as Record<string, unknown>);
  const documentCID = docEncoded.cid.toString();
  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID,
    baseDocumentCID: null,
    createdAt: ts(1),
    note: null,
  };
  const kid = `${identity.did}#${identity.authKey.keyId}`;
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op,
    signer: identity.authKey.signer,
    kid,
  });
  return { jwsToken, operationCID, documentCID };
};

/** Build a delegated content UPDATE signed by `delegate`, carrying an inline authorization. */
const delegatedUpdate = async (
  delegate: Awaited<ReturnType<typeof createIdentity>>,
  previousCID: string,
  documentCID: string,
  authorization: string,
  offset: number,
) => {
  const op = {
    version: 1 as const,
    type: 'update' as const,
    did: delegate.did,
    previousOperationCID: previousCID,
    documentCID,
    baseDocumentCID: null,
    createdAt: ts(offset),
    note: null,
    authorization,
  };
  const kid = `${delegate.did}#${delegate.authKey.keyId}`;
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op as unknown as ContentOperation,
    signer: delegate.authKey.signer,
    kid,
  });
  return { jwsToken, operationCID };
};

const newDoc = async (title: string) => {
  const doc = { type: 'post', title };
  const enc = await dagCborCanonicalEncode(doc as unknown as Record<string, unknown>);
  return enc.cid.toString();
};

describe('WP-4 write-path leaf revocation', () => {
  it('SECURITY: revoking the LEAF credential blocks the next delegated write', async () => {
    const store = new MemoryRelayStore();
    const creator = await createIdentity();
    const delegate = await createIdentity();
    const content = await createContentOp(creator);
    await ingestOperations([creator.jwsToken, delegate.jwsToken, content.jwsToken], store);

    // creator issues a write credential to the delegate (aud = delegate.did)
    const now = Math.floor(Date.now() / 1000);
    const { chainId: contentId } = (await ingestOperations([content.jwsToken], store))[0]!;
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${contentId}`, action: 'write' }],
      exp: now + 3600,
      signer: creator.authKey.signer,
      keyId: creator.authKey.keyId,
      iat: now,
    });

    // first delegated write — accepted
    const doc1 = await newDoc('first');
    const w1 = await delegatedUpdate(delegate, content.operationCID, doc1, credential, 2);
    const [r1] = await ingestOperations([w1.jwsToken], store);
    expect(r1!.status).toBe('new');

    // revoke the LEAF credential
    const credentialCID = decodeDFOSCredentialUnsafe(credential)!.header.cid;
    const { jwsToken: revocationJws } = await signRevocation({
      issuerDID: creator.did,
      credentialCID,
      signer: creator.authKey.signer,
      keyId: creator.authKey.keyId,
    });
    const [rev] = await ingestOperations([revocationJws], store);
    expect(rev!.status).toBe('new');

    // second delegated write under the NOW-REVOKED leaf — MUST be rejected
    const doc2 = await newDoc('second');
    const w2 = await delegatedUpdate(delegate, w1.operationCID, doc2, credential, 3);
    const [r2] = await ingestOperations([w2.jwsToken], store);
    expect(r2!.status).toBe('rejected');
    expect(r2!.error).toMatch(/revoked/);
  });
});

describe('WP-4 write-path parity (aud:* + action read,write)', () => {
  it('accepts an aud:* write credential presented inline', async () => {
    const store = new MemoryRelayStore();
    const creator = await createIdentity();
    const delegate = await createIdentity();
    const content = await createContentOp(creator);
    await ingestOperations([creator.jwsToken, delegate.jwsToken, content.jwsToken], store);
    const { chainId: contentId } = (await ingestOperations([content.jwsToken], store))[0]!;

    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: '*', // wildcard audience
      att: [{ resource: `chain:${contentId}`, action: 'write' }],
      exp: now + 3600,
      signer: creator.authKey.signer,
      keyId: creator.authKey.keyId,
      iat: now,
    });

    const doc = await newDoc('wild');
    const w = await delegatedUpdate(delegate, content.operationCID, doc, credential, 2);
    const [r] = await ingestOperations([w.jwsToken], store);
    expect(r!.status).toBe('new');
  });

  it("accepts a 'read,write' multi-action credential for a write", async () => {
    const store = new MemoryRelayStore();
    const creator = await createIdentity();
    const delegate = await createIdentity();
    const content = await createContentOp(creator);
    await ingestOperations([creator.jwsToken, delegate.jwsToken, content.jwsToken], store);
    const { chainId: contentId } = (await ingestOperations([content.jwsToken], store))[0]!;

    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${contentId}`, action: 'read,write' }],
      exp: now + 3600,
      signer: creator.authKey.signer,
      keyId: creator.authKey.keyId,
      iat: now,
    });

    const doc = await newDoc('rw');
    const w = await delegatedUpdate(delegate, content.operationCID, doc, credential, 2);
    const [r] = await ingestOperations([w.jwsToken], store);
    expect(r!.status).toBe('new');
  });
});
