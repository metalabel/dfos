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
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyIdentityChain,
} from '../src/chain';
import type { ContentOperation, IdentityOperation, MultikeyPublicKey } from '../src/chain';
import {
  dagCborCanonicalEncode,
  generateId,
  importEd25519Keypair,
  signPayloadEd25519,
} from '../src/crypto';

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

  console.log('\ndone — 5 fixtures generated');
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
