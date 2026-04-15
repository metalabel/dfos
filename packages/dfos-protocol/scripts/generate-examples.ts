/**
 * Generate deterministic example chain fixtures
 *
 * Uses fixed seeds so output is reproducible. The generated fixtures can be
 * independently verified by any Ed25519 + dag-cbor implementation.
 *
 * Usage: pnpm exec tsx scripts/generate-examples.ts
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeEd25519Multikey,
  signBeacon,
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyIdentityChain,
} from '../src/chain';
import type {
  BeaconPayload,
  ContentOperation,
  IdentityOperation,
  MultikeyPublicKey,
} from '../src/chain';
import { createDFOSCredential } from '../src/credentials';
import {
  dagCborCanonicalEncode,
  generateId,
  importEd25519Keypair,
  signPayloadEd25519,
} from '../src/crypto';

/** Fixed iat for deterministic credential examples (2026-03-07T00:00:00Z) */
const FIXED_IAT = Math.floor(new Date('2026-03-07T00:00:00.000Z').getTime() / 1000);

const sha256 = async (input: string) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)));

const __dirname = dirname(fileURLToPath(import.meta.url));

const main = async () => {
  const outDir = join(__dirname, '..', 'examples');
  mkdirSync(outDir, { recursive: true });

  // --- keys ---

  const seed1 = await sha256('dfos-protocol-reference-key-1');
  const keypair1 = importEd25519Keypair(seed1);
  const multikey1 = encodeEd25519Multikey(keypair1.publicKey);
  const keyId1 = generateId('key', { seed: keypair1.publicKey });
  const signer1 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair1.privateKey);

  const seed2 = await sha256('dfos-protocol-reference-key-2');
  const keypair2 = importEd25519Keypair(seed2);
  const multikey2 = encodeEd25519Multikey(keypair2.publicKey);
  const keyId2 = generateId('key', { seed: keypair2.publicKey });
  const signer2 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair2.privateKey);

  const key1: MultikeyPublicKey = {
    id: keyId1,
    type: 'Multikey',
    publicKeyMultibase: multikey1,
  };
  const key2: MultikeyPublicKey = {
    id: keyId2,
    type: 'Multikey',
    publicKeyMultibase: multikey2,
  };

  // ================================================================
  // IDENTITY FIXTURES
  // ================================================================

  // --- genesis ---
  const genesisOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key1],
    assertKeys: [key1],
    controllerKeys: [key1],
    createdAt: '2026-03-07T00:00:00.000Z',
  };
  const { jwsToken: genesisJws, operationCID: genesisCID } = await signIdentityOperation({
    operation: genesisOp,
    signer: signer1,
    keyId: keyId1,
  });
  const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesisJws] });

  // --- key rotation ---
  const rotateOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: genesisCID,
    authKeys: [key2],
    assertKeys: [key2],
    controllerKeys: [key2],
    createdAt: '2026-03-07T00:01:00.000Z',
  };
  const { jwsToken: rotateJws } = await signIdentityOperation({
    operation: rotateOp,
    signer: signer1,
    keyId: keyId1,
    identityDID: identity.did,
  });
  const identityRotated = await verifyIdentityChain({
    didPrefix: 'did:dfos',
    log: [genesisJws, rotateJws],
  });

  // --- delete ---
  const deleteIdentityOp: IdentityOperation = {
    version: 1,
    type: 'delete',
    previousOperationCID: genesisCID,
    createdAt: '2026-03-07T00:01:00.000Z',
  };
  const { jwsToken: deleteIdentityJws } = await signIdentityOperation({
    operation: deleteIdentityOp,
    signer: signer1,
    keyId: keyId1,
    identityDID: identity.did,
  });
  const identityDeleted = await verifyIdentityChain({
    didPrefix: 'did:dfos',
    log: [genesisJws, deleteIdentityJws],
  });

  // ================================================================
  // CONTENT FIXTURES
  // ================================================================

  const kid2 = `${identityRotated.did}#${keyId2}`;

  // --- create document (flat content object, no envelope) ---
  const document1 = {
    $schema: 'https://schemas.dfos.com/post/v1',
    format: 'short-post',
    title: 'Hello World',
    body: 'First post on the protocol.',
    createdByDID: identityRotated.did,
  };
  const doc1Block = await dagCborCanonicalEncode(document1);
  const documentCID1 = doc1Block.cid.toString();

  const contentCreateOp: ContentOperation = {
    version: 1,
    type: 'create',
    did: identityRotated.did,
    documentCID: documentCID1,
    baseDocumentCID: null,
    createdAt: '2026-03-07T00:02:00.000Z',
    note: null,
  };
  const { jwsToken: contentCreateJws, operationCID: contentCreateCID } = await signContentOperation(
    { operation: contentCreateOp, signer: signer2, kid: kid2 },
  );

  // --- update document ---
  const document2 = {
    $schema: 'https://schemas.dfos.com/post/v1',
    format: 'short-post',
    title: 'Hello World (edited)',
    body: 'Updated content.',
    createdByDID: identityRotated.did,
  };
  const doc2Block = await dagCborCanonicalEncode(document2);
  const documentCID2 = doc2Block.cid.toString();

  const contentUpdateOp: ContentOperation = {
    version: 1,
    type: 'update',
    did: identityRotated.did,
    previousOperationCID: contentCreateCID,
    documentCID: documentCID2,
    baseDocumentCID: documentCID1,
    createdAt: '2026-03-07T00:03:00.000Z',
    note: 'edited title and body',
  };
  const { jwsToken: contentUpdateJws } = await signContentOperation({
    operation: contentUpdateOp,
    signer: signer2,
    kid: kid2,
  });

  const contentChain = await verifyContentChain({
    log: [contentCreateJws, contentUpdateJws],
    resolveKey: async () => keypair2.publicKey,
  });

  // --- content delete ---
  const contentDeleteOp: ContentOperation = {
    version: 1,
    type: 'delete',
    did: identityRotated.did,
    previousOperationCID: contentCreateCID,
    createdAt: '2026-03-07T00:03:00.000Z',
    note: 'removing content',
  };
  const { jwsToken: contentDeleteJws } = await signContentOperation({
    operation: contentDeleteOp,
    signer: signer2,
    kid: kid2,
  });
  const contentDeleted = await verifyContentChain({
    log: [contentCreateJws, contentDeleteJws],
    resolveKey: async () => keypair2.publicKey,
  });

  // ================================================================
  // BEACON FIXTURE
  // ================================================================

  // Sign a beacon with key1 (controller)
  const kid1 = `${identity.did}#${keyId1}`;
  const beaconPayload: BeaconPayload = {
    version: 1,
    type: 'beacon',
    did: identity.did,
    manifestContentId: contentChain.contentId,
    createdAt: '2026-03-07T00:05:00.000Z',
  };
  const { jwsToken: beaconJws, beaconCID } = await signBeacon({
    payload: beaconPayload,
    signer: signer1,
    kid: kid1,
  });

  // Witness countersignature with key2
  const kid2Beacon = `${identity.did}#${keyId2}`;
  const { jwsToken: beaconWitnessJws } = await signBeacon({
    payload: beaconPayload,
    signer: signer2,
    kid: kid2Beacon,
  });

  // ================================================================
  // KEY 3 — DELEGATE IDENTITY
  // ================================================================

  // key3 is a third identity (separate DID) used as delegate in credential + chain fixtures
  const seed3 = await sha256('dfos-protocol-reference-key-3');
  const keypair3 = importEd25519Keypair(seed3);
  const multikey3 = encodeEd25519Multikey(keypair3.publicKey);
  const keyId3 = generateId('key', { seed: keypair3.publicKey });
  const signer3 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair3.privateKey);

  const key3: MultikeyPublicKey = {
    id: keyId3,
    type: 'Multikey',
    publicKeyMultibase: multikey3,
  };

  // derive a proper DID for key3 via identity genesis
  const key3GenesisOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key3],
    assertKeys: [key3],
    controllerKeys: [key3],
    createdAt: '2026-03-07T00:09:00.000Z',
  };
  const { jwsToken: key3GenesisJws } = await signIdentityOperation({
    operation: key3GenesisOp,
    signer: signer3,
    keyId: keyId3,
  });
  const identity3 = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [key3GenesisJws] });

  // ================================================================
  // CREDENTIAL FIXTURES
  // ================================================================

  // Write credential: key1 (controller) authorizes key3 (different DID) to write content chains
  const writeCredentialJws = await createDFOSCredential({
    issuerDID: identity.did,
    audienceDID: identity3.did,
    att: [{ resource: 'chain:*', action: 'write' }],
    exp: Math.floor(new Date('2027-01-01T00:00:00.000Z').getTime() / 1000),
    keyId: keyId1,
    iat: FIXED_IAT,
    signer: signer1,
  });

  // Write credential with contentId narrowing
  const narrowWriteCredentialJws = await createDFOSCredential({
    issuerDID: identity.did,
    audienceDID: identity3.did,
    att: [{ resource: 'chain:' + contentChain.contentId, action: 'write' }],
    exp: Math.floor(new Date('2027-01-01T00:00:00.000Z').getTime() / 1000),
    keyId: keyId1,
    iat: FIXED_IAT,
    signer: signer1,
  });

  // Read credential: key1 (controller) grants read access to key3
  const readCredentialJws = await createDFOSCredential({
    issuerDID: identity.did,
    audienceDID: identity3.did,
    att: [{ resource: 'chain:*', action: 'read' }],
    exp: Math.floor(new Date('2027-01-01T00:00:00.000Z').getTime() / 1000),
    keyId: keyId1,
    iat: FIXED_IAT,
    signer: signer1,
  });

  // ================================================================
  // DELEGATED CONTENT CHAIN FIXTURE
  // ================================================================

  // create a fresh content chain owned by identity (key1 controller)
  const delegatedDoc1 = {
    $schema: 'https://schemas.dfos.com/post/v1',
    format: 'short-post',
    title: 'Original Post',
    body: 'Content created by the chain owner.',
    createdByDID: identity.did,
  };
  const delegatedDoc1Block = await dagCborCanonicalEncode(delegatedDoc1);
  const delegatedDocCID1 = delegatedDoc1Block.cid.toString();

  const delegatedCreateOp: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID: delegatedDocCID1,
    baseDocumentCID: null,
    createdAt: '2026-03-07T00:10:00.000Z',
    note: null,
  };
  const { jwsToken: delegatedCreateJws, operationCID: delegatedCreateCID } =
    await signContentOperation({
      operation: delegatedCreateOp,
      signer: signer1,
      kid: kid1,
    });

  // verify to get contentId for narrowing
  const kid3 = `${identity3.did}#${keyId3}`;

  const delegatedChainGenesis = await verifyContentChain({
    log: [delegatedCreateJws],
    resolveKey: async () => keypair1.publicKey,
  });

  // key1 issues write VC to key3 (the delegate)
  const delegateWriteVC = await createDFOSCredential({
    issuerDID: identity.did,
    audienceDID: identity3.did,
    att: [{ resource: 'chain:' + delegatedChainGenesis.contentId, action: 'write' }],
    exp: Math.floor(new Date('2027-01-01T00:00:00.000Z').getTime() / 1000),
    keyId: keyId1,
    iat: FIXED_IAT,
    signer: signer1,
  });

  // key3 signs an update with the write VC
  const delegatedDoc2 = {
    $schema: 'https://schemas.dfos.com/post/v1',
    format: 'short-post',
    title: 'Delegated Edit',
    body: 'Content updated by an authorized delegate.',
    createdByDID: identity3.did,
  };
  const delegatedDoc2Block = await dagCborCanonicalEncode(delegatedDoc2);
  const delegatedDocCID2 = delegatedDoc2Block.cid.toString();

  const delegatedUpdateOp: ContentOperation = {
    version: 1,
    type: 'update',
    did: identity3.did,
    previousOperationCID: delegatedCreateCID,
    documentCID: delegatedDocCID2,
    baseDocumentCID: delegatedDocCID1,
    createdAt: '2026-03-07T00:11:00.000Z',
    note: 'delegated edit by key3',
    authorization: delegateWriteVC,
  };
  const { jwsToken: delegatedUpdateJws } = await signContentOperation({
    operation: delegatedUpdateOp,
    signer: signer3,
    kid: kid3,
  });

  // verify the delegated chain
  const delegatedContentChain = await verifyContentChain({
    log: [delegatedCreateJws, delegatedUpdateJws],
    resolveKey: async (resolvedKid: string) => {
      if (resolvedKid.includes(keyId1)) return keypair1.publicKey;
      if (resolvedKid.includes(keyId3)) return keypair3.publicKey;
      throw new Error(`unknown kid: ${resolvedKid}`);
    },
  });

  // ================================================================
  // WRITE FIXTURES
  // ================================================================

  const write = (name: string, data: unknown) => {
    const path = join(outDir, `${name}.json`);
    writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
    console.log(`wrote ${path}`);
  };

  write('identity-genesis', {
    description: 'Identity chain: genesis (single create operation)',
    type: 'identity',
    chain: [genesisJws],
    expected: {
      did: identity.did,
      isDeleted: false,
      controllerKeys: identity.controllerKeys,
    },
  });

  write('identity-rotation', {
    description: 'Identity chain: genesis + key rotation',
    type: 'identity',
    chain: [genesisJws, rotateJws],
    expected: {
      did: identityRotated.did,
      isDeleted: false,
      controllerKeys: identityRotated.controllerKeys,
    },
  });

  write('identity-delete', {
    description: 'Identity chain: genesis + delete (terminal)',
    type: 'identity',
    chain: [genesisJws, deleteIdentityJws],
    expected: {
      did: identityDeleted.did,
      isDeleted: true,
      controllerKeys: identityDeleted.controllerKeys,
    },
  });

  write('content-lifecycle', {
    description: 'Content chain: create + update (with both documents)',
    type: 'content',
    chain: [contentCreateJws, contentUpdateJws],
    signerPublicKey: multikey2,
    documents: [
      {
        content: document1,
        baseDocumentCID: null,
        createdByDID: identityRotated.did,
        createdAt: '2026-03-07T00:02:00.000Z',
      },
      {
        content: document2,
        baseDocumentCID: documentCID1,
        createdByDID: identityRotated.did,
        createdAt: '2026-03-07T00:03:00.000Z',
      },
    ],
    expected: {
      contentId: contentChain.contentId,
      isDeleted: false,
      currentDocumentCID: contentChain.currentDocumentCID,
      length: contentChain.length,
    },
  });

  write('content-delete', {
    description: 'Content chain: create + delete',
    type: 'content',
    chain: [contentCreateJws, contentDeleteJws],
    signerPublicKey: multikey2,
    documents: [
      {
        content: document1,
        baseDocumentCID: null,
        createdByDID: identityRotated.did,
        createdAt: '2026-03-07T00:02:00.000Z',
      },
    ],
    expected: {
      contentId: contentDeleted.contentId,
      isDeleted: true,
      currentDocumentCID: null,
      length: contentDeleted.length,
    },
  });

  write('beacon', {
    description: 'Beacon: signed manifest content ID announcement with witness countersignature',
    type: 'beacon',
    controllerJws: beaconJws,
    witnessJws: beaconWitnessJws,
    controllerPublicKey: multikey1,
    witnessPublicKey: multikey2,
    expected: {
      beaconCID,
      did: identity.did,
      manifestContentId: beaconPayload.manifestContentId,
      createdAt: beaconPayload.createdAt,
    },
  });

  write('credential-write', {
    description: 'DFOS credential: write access (broad + narrowed)',
    type: 'credential',
    broadCredential: writeCredentialJws,
    narrowCredential: narrowWriteCredentialJws,
    issuerPublicKey: multikey1,
    audiencePublicKey: multikey3,
    expected: {
      iss: identity.did,
      aud: identity3.did,
      narrowContentId: contentChain.contentId,
    },
  });

  write('credential-read', {
    description: 'DFOS credential: read access',
    type: 'credential',
    credential: readCredentialJws,
    issuerPublicKey: multikey1,
    audiencePublicKey: multikey3,
    expected: {
      iss: identity.did,
      aud: identity3.did,
    },
  });

  write('content-delegated', {
    description:
      'Content chain: creator signs genesis, delegate signs update with write credential',
    type: 'content-delegated',
    chain: [delegatedCreateJws, delegatedUpdateJws],
    creatorPublicKey: multikey1,
    delegatePublicKey: multikey3,
    documents: [
      {
        content: delegatedDoc1,
        baseDocumentCID: null,
        createdByDID: identity.did,
        createdAt: '2026-03-07T00:10:00.000Z',
      },
      {
        content: delegatedDoc2,
        baseDocumentCID: delegatedDocCID1,
        createdByDID: identity3.did,
        createdAt: '2026-03-07T00:11:00.000Z',
      },
    ],
    authorization: delegateWriteVC,
    expected: {
      contentId: delegatedContentChain.contentId,
      creatorDID: identity.did,
      isDeleted: false,
      currentDocumentCID: delegatedContentChain.currentDocumentCID,
      length: 2,
    },
  });

  console.log('\ndone — 9 fixtures generated');
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
