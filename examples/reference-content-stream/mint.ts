/*

  MINT THE REFERENCE CONTENT STREAM FIXTURE

  Regenerates chain.json and projected-state.json from fixed seeds. Every DID,
  CID, credential, and JWS in the fixture is real: the script builds three
  identity chains, one content chain, two write credentials, and six signed
  content operations, then runs verifyContentChain over the log before it
  writes anything.

  Deterministic by construction. The seeds below are fixed, Ed25519 signatures
  are deterministic (RFC 8032), and every timestamp is a literal, so running
  this twice produces byte-identical files.

  Run: pnpm --filter @metalabel/dfos-protocol exec tsx ../../examples/reference-content-stream/mint.ts

*/

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createDFOSCredential,
  dagCborCanonicalEncode,
  encodeEd25519Multikey,
  generateId,
  importEd25519Keypair,
  parseProtocolTimestampUnix,
  sha256,
  signContentOperation,
  signIdentityOperation,
  signPayloadEd25519,
  verifyContentChain,
  verifyIdentityChain,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
  type VerifiedIdentity,
} from '../../packages/dfos-protocol/src/index';

// -----------------------------------------------------------------------------
// fixed inputs
// -----------------------------------------------------------------------------

const SCHEMA = 'https://schemas.dfos.com/reference-content-stream/v1';

/** Private key seeds. 32 bytes each, SHA-256 of a fixed label. */
const KEY_SEED_LABEL = (name: string) => `dfos-reference-content-stream-key-${name}`;

/** Key id seeds. Fixed so the `key_…` identifiers are stable across runs. */
const KEY_ID_SEED_LABEL = (name: string) => `dfos-reference-content-stream-keyid-${name}`;

/** Identity genesis timestamp, shared by all three participants. */
const IDENTITY_CREATED_AT = '2026-03-25T00:00:00.000Z';

/** Credential issue instant, before the first content operation. */
const CREDENTIAL_IAT = '2026-03-25T00:30:00.000Z';

/** Credential expiry. Far enough out that every operation basis is inside it. */
const CREDENTIAL_EXP = '2036-03-25T00:00:00.000Z';

/** One timestamp per content operation, strictly increasing. */
const OPERATION_CREATED_AT = [
  '2026-03-25T01:00:00.000Z',
  '2026-03-25T01:10:00.000Z',
  '2026-03-25T01:20:00.000Z',
  '2026-03-25T01:30:00.000Z',
  '2026-03-25T01:40:00.000Z',
  '2026-03-25T01:50:00.000Z',
];

const unix = (iso: string): number => {
  const seconds = parseProtocolTimestampUnix(iso);
  if (seconds === null) throw new Error(`not a protocol timestamp: ${iso}`);
  return seconds;
};

const utf8 = (value: string) => new TextEncoder().encode(value);

// -----------------------------------------------------------------------------
// participants
// -----------------------------------------------------------------------------

interface Participant {
  name: string;
  did: string;
  keyId: string;
  kid: string;
  publicKey: Uint8Array;
  signer: (message: Uint8Array) => Promise<Uint8Array>;
  identity: VerifiedIdentity;
}

const makeParticipant = async (name: string): Promise<Participant> => {
  const { privateKey, publicKey } = importEd25519Keypair(sha256(utf8(KEY_SEED_LABEL(name))));
  const keyId = generateId('key', { seed: utf8(KEY_ID_SEED_LABEL(name)) });
  const signer = async (message: Uint8Array) => signPayloadEd25519(message, privateKey);

  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(publicKey),
  };
  const genesis: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key],
    assertKeys: [key],
    controllerKeys: [key],
    createdAt: IDENTITY_CREATED_AT,
  };
  const { jwsToken } = await signIdentityOperation({ operation: genesis, signer, keyId });
  const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] });

  return {
    name,
    did: identity.did,
    keyId,
    kid: `${identity.did}#${keyId}`,
    publicKey,
    signer,
    identity,
  };
};

// -----------------------------------------------------------------------------
// documents
// -----------------------------------------------------------------------------

interface StreamDocument {
  $schema: string;
  action: 'create-item' | 'update-item' | 'delete-item' | 'react' | 'unreact';
  createdByDID: string;
  title?: string;
  body?: string;
  targetOperationCID?: string;
  reaction?: string;
}

const documentCIDOf = async (document: StreamDocument): Promise<string> => {
  const encoded = await dagCborCanonicalEncode(document);
  return encoded.cid.toString();
};

// -----------------------------------------------------------------------------
// mint
// -----------------------------------------------------------------------------

const main = async () => {
  const alice = await makeParticipant('alice');
  const bob = await makeParticipant('bob');
  const carol = await makeParticipant('carol');

  const byDID = new Map<string, Participant>([alice, bob, carol].map((p) => [p.did, p] as const));
  const byKid = new Map<string, Participant>([alice, bob, carol].map((p) => [p.kid, p] as const));

  const resolveKey = async (kid: string) => {
    const participant = byKid.get(kid);
    if (!participant) throw new Error(`unknown kid: ${kid}`);
    return participant.publicKey;
  };
  const resolveIdentity = async (did: string) => byDID.get(did)?.identity;

  // alice owns the chain and delegates write on every chain she owns
  const writeCredential = (audience: Participant) =>
    createDFOSCredential({
      issuerDID: alice.did,
      audienceDID: audience.did,
      att: [{ resource: 'chain:*', action: 'write' }],
      exp: unix(CREDENTIAL_EXP),
      iat: unix(CREDENTIAL_IAT),
      signer: alice.signer,
      keyId: alice.keyId,
    });
  const credentials = new Map<string, string>([
    [bob.did, await writeCredential(bob)],
    [carol.did, await writeCredential(carol)],
  ]);

  interface MintedOperation {
    sequence: number;
    operationCID: string;
    documentCID: string;
    action: string;
    document: StreamDocument;
    jws: string;
  }

  const minted: MintedOperation[] = [];
  const log: string[] = [];
  let previousOperationCID: string | null = null;

  const append = async (author: Participant, build: () => StreamDocument) => {
    const sequence = minted.length;
    const document = build();
    const documentCID = await documentCIDOf(document);
    const createdAt = OPERATION_CREATED_AT[sequence];
    if (createdAt === undefined) throw new Error(`no timestamp for sequence ${sequence}`);

    const operation: ContentOperation =
      previousOperationCID === null
        ? {
            version: 1,
            type: 'create',
            did: author.did,
            documentCID,
            baseDocumentCID: null,
            createdAt,
          }
        : {
            version: 1,
            type: 'update',
            did: author.did,
            previousOperationCID,
            documentCID,
            baseDocumentCID: null,
            createdAt,
            ...(author.did === alice.did ? {} : { authorization: credentials.get(author.did) }),
          };

    const { jwsToken, operationCID } = await signContentOperation({
      operation,
      signer: author.signer,
      kid: author.kid,
    });

    minted.push({
      sequence,
      operationCID,
      documentCID,
      action: document.action,
      document,
      jws: jwsToken,
    });
    log.push(jwsToken);
    previousOperationCID = operationCID;
    return operationCID;
  };

  // 1. alice creates "Hello world"
  const item1 = await append(alice, () => ({
    $schema: SCHEMA,
    action: 'create-item',
    createdByDID: alice.did,
    title: 'Hello world',
    body: 'My first post.',
  }));

  // 2. bob creates "Second item"
  const item2 = await append(bob, () => ({
    $schema: SCHEMA,
    action: 'create-item',
    createdByDID: bob.did,
    title: 'Second item',
    body: "Bob's contribution.",
  }));

  // 3. carol reacts to item 1
  await append(carol, () => ({
    $schema: SCHEMA,
    action: 'react',
    createdByDID: carol.did,
    targetOperationCID: item1,
    reaction: 'thumbsup',
  }));

  // 4. alice edits item 1
  const item1Edit = await append(alice, () => ({
    $schema: SCHEMA,
    action: 'update-item',
    createdByDID: alice.did,
    targetOperationCID: item1,
    title: 'Hello world (edited)',
    body: 'My first post, now edited.',
  }));

  // 5. alice reacts to item 2
  await append(alice, () => ({
    $schema: SCHEMA,
    action: 'react',
    createdByDID: alice.did,
    targetOperationCID: item2,
    reaction: 'fire',
  }));

  // 6. bob deletes item 2
  const item2Delete = await append(bob, () => ({
    $schema: SCHEMA,
    action: 'delete-item',
    createdByDID: bob.did,
    targetOperationCID: item2,
  }));

  // the fixture is written only if the chain it describes verifies
  const verified = await verifyContentChain({
    log,
    resolveKey,
    enforceAuthorization: true,
    resolveIdentity,
  });
  if (verified.length !== minted.length) {
    throw new Error(`verified ${verified.length} operations, minted ${minted.length}`);
  }
  if (verified.creatorDID !== alice.did) {
    throw new Error(`unexpected creator ${verified.creatorDID}`);
  }

  const chain = {
    description: 'Six operations demonstrating reference-content-stream/v1 lifecycle',
    schema: SCHEMA,
    contentId: verified.contentId,
    participants: { alice: alice.did, bob: bob.did, carol: carol.did },
    operations: minted,
  };

  const projectedState = {
    description: 'Expected state after folding all 6 operations from chain.json',
    items: [
      {
        operationCID: item1Edit,
        originalOperationCID: item1,
        title: 'Hello world (edited)',
        body: 'My first post, now edited.',
        createdByDID: alice.did,
      },
    ],
    deletedItems: [
      {
        operationCID: item2,
        deletedByOperationCID: item2Delete,
        title: 'Second item',
        createdByDID: bob.did,
      },
    ],
    reactions: [
      {
        targetOperationCID: item1,
        reaction: 'thumbsup',
        createdByDID: carol.did,
      },
    ],
    droppedReactions: [
      {
        targetOperationCID: item2,
        reaction: 'fire',
        createdByDID: alice.did,
        reason: 'target item was deleted',
      },
    ],
    note: "Item 2 was deleted in op6, which also dropped alice's fire reaction from op5. Carol's thumbsup on item 1 survives because item 1 was only edited, not deleted.",
  };

  const here = dirname(fileURLToPath(import.meta.url));
  const write = (name: string, value: unknown) =>
    writeFileSync(join(here, name), `${JSON.stringify(value, null, 2)}\n`);

  write('chain.json', chain);
  write('projected-state.json', projectedState);

  console.log(`minted ${minted.length} operations on chain ${verified.contentId}`);
};

await main();
