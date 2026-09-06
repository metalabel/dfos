/**
 * Protocol reference — generates deterministic artifacts for the spec doc AND
 * asserts them against the golden values checked into specs/PROTOCOL.md and
 * the examples/ fixtures (the drift guard).
 *
 * Uses fixed seeds so output is reproducible. Every value generated here can be
 * independently verified by any Ed25519 + dag-cbor implementation.
 *
 * Two responsibilities:
 *
 *  1. `generates all reference data` — the printer. Regenerates all deterministic
 *     artifacts and console.logs them. Run with `--disableConsoleIntercept` to
 *     copy fresh values into specs/PROTOCOL.md when intentionally changing a vector.
 *
 *  2. `matches the golden values ...` — the drift guard. Parses the JWS tokens /
 *     CIDs / keys back OUT of specs/PROTOCOL.md (and the examples/ fixtures) at
 *     test time and asserts the freshly-generated value is byte-identical. If any
 *     PROTOCOL.md vector is corrupted (e.g. #57: a one-char-flipped genesis JWS),
 *     this test FAILS. The previous version of this file had zero assertions — it
 *     was a pure printer, which is exactly why #57 shipped undetected.
 */

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  decodeMultikey,
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyIdentityChain,
} from '../src/chain';
import type { ContentOperation, IdentityOperation, MultikeyPublicKey } from '../src/chain';
import { createDFOSCredential } from '../src/credentials';
import {
  base64urlDecode,
  base64urlEncode,
  createJwt,
  dagCborCanonicalEncode,
  generateId,
  importEd25519Keypair,
  signPayloadEd25519,
  verifyJwt,
} from '../src/crypto';
import {
  KEY_ADD_JWS_TYP,
  keyProofSigningInput,
  serializeRoleSet,
  signKeyProof,
  type KeyProofPayload,
} from '../src/key-proof';

/**
 * The reference key-proof envelope's fixed inputs. Kept byte-identical with
 * scripts/generate-examples.ts, so the rotation fixture in examples/ and the
 * spec's deterministic artifacts are the same operation.
 */
const REFERENCE_KEY_PROOF_NONCE = 'dfos-protocol-reference-nonce-1';
const REFERENCE_KEY_PROOF_AUDIENCE = 'keys.dfos.com';
const REFERENCE_KEY_PROOF_TIMESTAMP = '2026-03-07T00:00:30.000Z';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const DIV = (t: string) => console.log(`\n${'='.repeat(80)}\n${t}\n${'='.repeat(80)}\n`);

const decodeParts = (token: string) => {
  const [h, p, s] = token.split('.') as [string, string, string];
  return {
    header: JSON.parse(new TextDecoder().decode(base64urlDecode(h))),
    payload: JSON.parse(new TextDecoder().decode(base64urlDecode(p))),
    signatureHex: hex(base64urlDecode(s)),
  };
};

/**
 * The complete set of deterministically-generated reference artifacts. These are
 * the values the spec doc and example fixtures pin. Generated once, then either
 * printed (printer) or asserted byte-for-byte against the goldens (drift guard).
 */
interface ReferenceArtifacts {
  privateKey1Hex: string;
  publicKey1Hex: string;
  multikey1: string;
  keyId1: string;
  privateKey2Hex: string;
  publicKey2Hex: string;
  multikey2: string;
  keyId2: string;
  did: string;
  // identity chain
  genesisOp: IdentityOperation;
  genesisJws: string;
  genesisCID: string;
  genesisSignatureHex: string;
  genesisHeader: Record<string, unknown>;
  genesisCborHex: string;
  genesisCidBytesHex: string;
  updateOp: IdentityOperation;
  updateJws: string;
  updateCID: string;
  updateSignatureHex: string;
  updateHeader: Record<string, unknown>;
  // the possession proof the rotation carries
  keyProof: string;
  keyProofPayload: KeyProofPayload;
  keyProofCanonical: string;
  keyProofHeader: Record<string, unknown>;
  keyProofSignatureHex: string;
  deleteOp: IdentityOperation;
  deleteJws: string;
  deleteCID: string;
  deleteSignatureHex: string;
  deleteHeader: Record<string, unknown>;
  restoreOp: IdentityOperation;
  restoreJws: string;
  restoreCID: string;
  restoreSignatureHex: string;
  restoreHeader: Record<string, unknown>;
  // content chain
  contentCreateDocument: Record<string, unknown>;
  documentCID: string;
  contentCreateOp: ContentOperation;
  contentCreateJws: string;
  contentCreateCID: string;
  contentCreateSignatureHex: string;
  contentCreateHeader: Record<string, unknown>;
  contentUpdateDocument: Record<string, unknown>;
  documentCID2: string;
  contentUpdateOp: ContentOperation;
  contentUpdateJws: string;
  contentUpdateCID: string;
  contentId: string;
  contentGenesisCID: string;
  contentHeadCID: string;
  // jwt
  jwt: string;
  jwtSubject: string;
}

async function generateReferenceArtifacts(): Promise<ReferenceArtifacts> {
  // ----------------------------------------------------------------
  // Deterministic Ed25519 keypairs — sha256 of fixed strings as seeds.
  // ----------------------------------------------------------------
  const seed1 = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('dfos-protocol-reference-key-1'),
    ),
  );
  const keypair1 = importEd25519Keypair(seed1);
  const multikey1 = encodeEd25519Multikey(keypair1.publicKey);
  const keyId1 = generateId('key', { seed: keypair1.publicKey });

  const seed2 = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('dfos-protocol-reference-key-2'),
    ),
  );
  const keypair2 = importEd25519Keypair(seed2);
  const multikey2 = encodeEd25519Multikey(keypair2.publicKey);
  const keyId2 = generateId('key', { seed: keypair2.publicKey });

  // ----------------------------------------------------------------
  // Identity chain: create (genesis)
  // ----------------------------------------------------------------
  const key1: MultikeyPublicKey = { id: keyId1, type: 'Multikey', publicKeyMultibase: multikey1 };
  const signer1 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair1.privateKey);

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
  const genParts = decodeParts(genesisJws);
  const genesisEncoded = await dagCborCanonicalEncode(genesisOp);

  const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesisJws] });
  const did = identity.did;

  // ----------------------------------------------------------------
  // Identity chain: update (key rotation)
  // ----------------------------------------------------------------
  const key2: MultikeyPublicKey = { id: keyId2, type: 'Multikey', publicKeyMultibase: multikey2 };

  // The rotation INTRODUCES key 2 to all three roles, so it carries key 2's own
  // possession proof, headed at the genesis CID. Signed by key 2 — the key being
  // introduced — while the OPERATION is signed by key 1. Two different keys sign
  // two different things, and that is the whole rotation ceremony in miniature:
  // the outgoing controller authorizes the change, the incoming key consents to
  // the position.
  const { proof: keyProof, payload: keyProofPayload } = await signKeyProof({
    typ: KEY_ADD_JWS_TYP,
    nonce: REFERENCE_KEY_PROOF_NONCE,
    audience: REFERENCE_KEY_PROOF_AUDIENCE,
    did,
    roleSet: serializeRoleSet(['auth', 'assert', 'controller']),
    prevCID: genesisCID,
    privateKey: keypair2.privateKey,
    timestamp: REFERENCE_KEY_PROOF_TIMESTAMP,
  });
  const keyProofParts = decodeParts(keyProof);

  const updateOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: genesisCID,
    authKeys: [key2],
    assertKeys: [key2],
    controllerKeys: [key2],
    createdAt: '2026-03-07T00:01:00.000Z',
    keyProofs: [keyProof],
  };
  const { jwsToken: updateJws, operationCID: updateCID } = await signIdentityOperation({
    operation: updateOp,
    signer: signer1, // OLD key signs rotation
    keyId: keyId1,
    identityDID: did,
  });
  const updParts = decodeParts(updateJws);

  const identity2 = await verifyIdentityChain({
    didPrefix: 'did:dfos',
    log: [genesisJws, updateJws],
  });
  // The proof is what puts key 2 into EFFECTIVE state. A reference chain whose
  // rotation went void would be a reference chain nobody could sign with.
  if (identity2.controllerKeys[0]?.id !== keyId2 || (identity2.voidKeys ?? []).length > 0) {
    throw new Error('reference rotation did not put key 2 into effective state');
  }

  // ----------------------------------------------------------------
  // Identity chain: delete + restore
  // ----------------------------------------------------------------
  const signer2 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair2.privateKey);
  const deleteOp: IdentityOperation = {
    version: 1,
    type: 'delete',
    previousOperationCID: updateCID,
    createdAt: '2026-03-07T00:02:00.000Z',
  };
  const { jwsToken: deleteJws, operationCID: deleteCID } = await signIdentityOperation({
    operation: deleteOp,
    signer: signer2,
    keyId: keyId2,
    identityDID: did,
  });
  const delParts = decodeParts(deleteJws);
  const restoreOp: IdentityOperation = {
    version: 1,
    type: 'restore',
    previousOperationCID: deleteCID,
    createdAt: '2026-03-07T00:03:00.000Z',
  };
  const { jwsToken: restoreJws, operationCID: restoreCID } = await signIdentityOperation({
    operation: restoreOp,
    signer: signer2,
    keyId: keyId2,
    identityDID: did,
  });
  const resParts = decodeParts(restoreJws);
  const restoredIdentity = await verifyIdentityChain({
    didPrefix: 'did:dfos',
    log: [genesisJws, updateJws, deleteJws, restoreJws],
  });
  if (restoredIdentity.isDeleted || restoredIdentity.controllerKeys[0]?.id !== keyId2) {
    throw new Error('delete + restore reference chain did not retain the rotated key state');
  }

  // ----------------------------------------------------------------
  // Content chain: document + create
  // ----------------------------------------------------------------
  const kid2 = `${identity2.did}#${keyId2}`;

  const document = {
    $schema: 'https://schemas.dfos.com/post/v1',
    format: 'short-post',
    publishedAt: '2026-03-07T00:02:00.000Z',
    title: 'Hello World',
    body: 'First post on the protocol.',
    credits: [{ did: identity2.did, label: 'author' }],
  };
  const docBlock = await dagCborCanonicalEncode(document);
  const documentCID = docBlock.cid.toString();

  const createContentOp: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity2.did,
    documentCID,
    baseDocumentCID: null,
    createdAt: '2026-03-07T00:02:00.000Z',
  };
  const { jwsToken: contentCreateJws, operationCID: contentCreateCID } = await signContentOperation(
    {
      operation: createContentOp,
      signer: signer2,
      kid: kid2,
    },
  );
  const ccParts = decodeParts(contentCreateJws);

  // ----------------------------------------------------------------
  // Content chain: update
  // ----------------------------------------------------------------
  const document2 = {
    $schema: 'https://schemas.dfos.com/post/v1',
    format: 'short-post',
    publishedAt: '2026-03-07T00:02:00.000Z',
    title: 'Hello World (edited)',
    body: 'Updated content.',
    credits: [{ did: identity2.did, label: 'author' }],
  };
  const doc2Block = await dagCborCanonicalEncode(document2);
  const documentCID2 = doc2Block.cid.toString();

  const updateContentOp: ContentOperation = {
    version: 1,
    type: 'update',
    did: identity2.did,
    previousOperationCID: contentCreateCID,
    documentCID: documentCID2,
    baseDocumentCID: documentCID,
    createdAt: '2026-03-07T00:03:00.000Z',
  };
  const { jwsToken: contentUpdateJws, operationCID: contentUpdateCID } = await signContentOperation(
    {
      operation: updateContentOp,
      signer: signer2,
      kid: kid2,
    },
  );

  const contentChain = await verifyContentChain({
    log: [contentCreateJws, contentUpdateJws],
    resolveKey: async () => keypair2.publicKey,
  });

  // ----------------------------------------------------------------
  // JWT (device auth)
  // ----------------------------------------------------------------
  const jwt = await createJwt({
    header: { alg: 'EdDSA', typ: 'JWT', kid: keyId2 },
    payload: {
      iss: 'dfos',
      sub: identity2.did,
      aud: 'dfos-api',
      exp: 1772902800,
      iat: 1772899200,
      jti: 'session_ref_example_01',
    },
    sign: signer2,
  });
  const jwtResult = verifyJwt({
    token: jwt,
    publicKey: keypair2.publicKey,
    issuer: 'dfos',
    audience: 'dfos-api',
    currentTime: 1772899200,
  });

  return {
    privateKey1Hex: hex(keypair1.privateKey),
    publicKey1Hex: hex(keypair1.publicKey),
    multikey1,
    keyId1,
    privateKey2Hex: hex(keypair2.privateKey),
    publicKey2Hex: hex(keypair2.publicKey),
    multikey2,
    keyId2,
    did,
    genesisOp,
    genesisJws,
    genesisCID,
    genesisSignatureHex: genParts.signatureHex,
    genesisHeader: genParts.header,
    genesisCborHex: hex(genesisEncoded.bytes),
    genesisCidBytesHex: hex(genesisEncoded.cid.bytes),
    updateOp,
    updateJws,
    updateCID,
    updateSignatureHex: updParts.signatureHex,
    updateHeader: updParts.header,
    keyProof,
    keyProofPayload,
    keyProofCanonical: new TextDecoder().decode(keyProofSigningInput(keyProofPayload)),
    keyProofHeader: keyProofParts.header,
    keyProofSignatureHex: keyProofParts.signatureHex,
    deleteOp,
    deleteJws,
    deleteCID,
    deleteSignatureHex: delParts.signatureHex,
    deleteHeader: delParts.header,
    restoreOp,
    restoreJws,
    restoreCID,
    restoreSignatureHex: resParts.signatureHex,
    restoreHeader: resParts.header,
    contentCreateDocument: document,
    documentCID,
    contentCreateOp: createContentOp,
    contentCreateJws,
    contentCreateCID,
    contentCreateSignatureHex: ccParts.signatureHex,
    contentCreateHeader: ccParts.header,
    contentUpdateDocument: document2,
    documentCID2,
    contentUpdateOp: updateContentOp,
    contentUpdateJws,
    contentUpdateCID,
    contentId: contentChain.contentId,
    contentGenesisCID: contentChain.genesisCID,
    contentHeadCID: contentChain.headCID,
    jwt,
    jwtSubject: jwtResult.payload.sub,
  };
}

// =============================================================================
// The shared cross-language vector artifact
// =============================================================================
//
// packages/protocol-verify/vectors.json is the ONE place the five standalone
// verification suites and the Go twin's reference tests read their expected
// values from. This file is its generator: every field below is DERIVED from
// the fixed reference seeds, never transcribed. The check at the bottom asserts
// the checked-in artifact is byte-identical to a fresh generation, so the
// artifact can never drift from the TypeScript reference — and, because every
// suite reads it, no suite can drift into a private copy of a vector.
//
// Regenerate intentionally (after deliberately changing a vector) with:
//   UPDATE_VECTORS=1 pnpm --filter @metalabel/dfos-protocol exec vitest run tests/protocol-reference.spec.ts

/** Fixed iat/exp for the deterministic credential vectors. */
const REFERENCE_CREDENTIAL_IAT = Math.floor(new Date('2026-03-07T00:00:00.000Z').getTime() / 1000);
const REFERENCE_CREDENTIAL_EXP = Math.floor(new Date('2027-01-01T00:00:00.000Z').getTime() / 1000);

/** Ed25519 group order L, little-endian — the S < L canonical bound. */
const ED25519_L = new Uint8Array([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]);

interface VectorEntry {
  id: string;
  description: string;
  values: Record<string, unknown>;
}

interface VectorsDocument {
  version: number;
  description: string;
  generator: string;
  vectors: VectorEntry[];
}

/** CIDv1 (dag-cbor codec, sha2-256) over arbitrary bytes, as a base32lower string. */
const cidOverBytes = async (bytes: Uint8Array): Promise<string> => {
  const { CID } = await import('multiformats/cid');
  const { sha256: mfSha256 } = await import('multiformats/hashes/sha2');
  return CID.createV1(0x71, await mfSha256.digest(bytes)).toString();
};

const toHex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

/**
 * Generate the complete shared-vector document from the reference seeds. Takes
 * the already-generated chain artifacts and adds the vectors the five
 * standalone suites also assert: the services genesis, the two credentials, the
 * reject corpus, and the WP-0 number-policy CIDs.
 */
async function generateSharedVectors(a: ReferenceArtifacts): Promise<VectorsDocument> {
  const digest = async (input: string) =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)));

  const keypair1 = importEd25519Keypair(await digest('dfos-protocol-reference-key-1'));
  const keypair2 = importEd25519Keypair(await digest('dfos-protocol-reference-key-2'));
  const keypair3 = importEd25519Keypair(await digest('dfos-protocol-reference-key-3'));
  const signer1 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair1.privateKey);
  const signer3 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair3.privateKey);

  const keyId1 = generateId('key', { seed: keypair1.publicKey });
  const keyId3 = generateId('key', { seed: keypair3.publicKey });
  const multikey3 = encodeEd25519Multikey(keypair3.publicKey);
  const key1: MultikeyPublicKey = {
    id: keyId1,
    type: 'Multikey',
    publicKeyMultibase: a.multikey1,
  };
  const key3: MultikeyPublicKey = { id: keyId3, type: 'Multikey', publicKeyMultibase: multikey3 };

  // --- key 3: the delegate identity the credentials are issued TO ---
  const { jwsToken: key3GenesisJws } = await signIdentityOperation({
    operation: {
      version: 1,
      type: 'create',
      authKeys: [key3],
      assertKeys: [key3],
      controllerKeys: [key3],
      createdAt: '2026-03-07T00:09:00.000Z',
    },
    signer: signer3,
    keyId: keyId3,
  });
  const identity3 = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [key3GenesisJws] });

  // --- services genesis: a create carrying a full-state services array ---
  const servicesGenesisOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key1],
    assertKeys: [key1],
    controllerKeys: [key1],
    services: [
      { id: 'relay', type: 'DfosRelay', endpoint: 'https://relay.dfos.com' },
      { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: a.contentId },
      { id: 'avatar', type: 'ContentAnchor', label: 'avatar', anchor: a.documentCID },
    ],
    createdAt: '2026-03-07T00:05:00.000Z',
  };
  const { jwsToken: servicesGenesisJws, operationCID: servicesGenesisCID } =
    await signIdentityOperation({ operation: servicesGenesisOp, signer: signer1, keyId: keyId1 });
  const servicesIdentity = await verifyIdentityChain({
    didPrefix: 'did:dfos',
    log: [servicesGenesisJws],
  });

  // --- credentials: key 1 (controller) authorizes key 3's DID ---
  const credential = (action: 'write' | 'read') =>
    createDFOSCredential({
      issuerDID: a.did,
      audienceDID: identity3.did,
      att: [{ resource: 'chain:*', action }],
      exp: REFERENCE_CREDENTIAL_EXP,
      iat: REFERENCE_CREDENTIAL_IAT,
      keyId: keyId1,
      signer: signer1,
    });
  const writeCredentialJws = await credential('write');
  const readCredentialJws = await credential('read');

  // --- reject corpus: one valid base vector, then nine targeted mutations ---
  // Every conformant verifier MUST reject all nine. The base vector itself is
  // valid, so each rejection isolates exactly one profile or signature gate.
  const rejectHeader = {
    alg: 'EdDSA',
    typ: 'did:dfos:reject-vector',
    kid: 'key_r9ev34fvc23z999veaaft8',
  };
  const encodeSegment = (value: unknown) => base64urlEncode(JSON.stringify(value));
  const rejectHeaderB64 = encodeSegment(rejectHeader);
  const rejectPayloadB64 = encodeSegment({ v: 1 });
  const rejectSignature = await signPayloadEd25519(
    new TextEncoder().encode(`${rejectHeaderB64}.${rejectPayloadB64}`),
    keypair1.privateKey,
  );
  const rejectToken = (headerB64: string, signature: Uint8Array) =>
    `${headerB64}.${rejectPayloadB64}.${base64urlEncode(signature)}`;
  const mutateSignature = (mutate: (sig: Uint8Array) => Uint8Array) =>
    rejectToken(rejectHeaderB64, mutate(new Uint8Array(rejectSignature)));
  const mutateHeader = (extra: Record<string, unknown>) =>
    rejectToken(encodeSegment({ ...rejectHeader, ...extra }), rejectSignature);

  const sPlusL = (sig: Uint8Array) => {
    const out = new Uint8Array(sig);
    let carry = 0;
    for (let i = 0; i < 32; i++) {
      const sum = sig[32 + i]! + ED25519_L[i]! + carry;
      out[32 + i] = sum & 0xff;
      carry = sum >> 8;
    }
    return out;
  };

  const rejectVectors: Record<string, string> = {
    'RV-LEN-SHORT': mutateSignature((sig) => sig.slice(0, 63)),
    'RV-LEN-LONG': mutateSignature((sig) => new Uint8Array([...sig, 0x00])),
    'RV-S-NONCANON-PLUSL': mutateSignature(sPlusL),
    'RV-S-NONCANON-FF': mutateSignature(
      (sig) => new Uint8Array([...sig.slice(0, 32), ...new Uint8Array(32).fill(0xff)]),
    ),
    'RV-ALG-NONE': mutateHeader({ alg: 'none' }),
    'RV-ALG-CASE': mutateHeader({ alg: 'eddsa' }),
    'RV-CRIT-PRESENT': mutateHeader({ crit: ['exp'] }),
    'RV-HEADER-KEY-TRUST': mutateHeader({ jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } }),
    'RV-SIG-BITFLIP': mutateSignature((sig) => {
      const out = new Uint8Array(sig);
      out[63] = out[63]! ^ 0x01;
      return out;
    }),
  };

  // --- WP-0 number policy ---
  const integerValue = { version: 1, type: 'test' };
  const integerBlock = await dagCborCanonicalEncode(integerValue);
  // The serialization a conforming encoder MUST NOT emit: the same map with
  // `version` as a CBOR float16 1.0 (0xf9 0x3c00 — what a deterministic CBOR
  // encoder emits for a whole-number float) in place of the integer 1. Derived
  // from the canonical bytes by replacing the trailing integer byte, so it stays
  // tied to the canonical encoding rather than transcribed. This is the byte at
  // offset 19 the spec calls the discriminator.
  const floatVersionCbor = new Uint8Array([
    ...integerBlock.bytes.slice(0, integerBlock.bytes.length - 1),
    0xf9,
    0x3c,
    0x00,
  ]);
  const maxSafeValue = { n: Number.MAX_SAFE_INTEGER };
  const maxSafeBlock = await dagCborCanonicalEncode(maxSafeValue);
  const nullValue = { documentCID: null, note: null, prf: [] };
  const nullBlock = await dagCborCanonicalEncode(nullValue);

  const vectors: VectorEntry[] = [
    {
      id: 'key-1',
      description: 'Reference key 1 — the genesis controller. Seed is SHA-256 of the seed phrase.',
      values: {
        seedPhrase: 'dfos-protocol-reference-key-1',
        privateKeyHex: a.privateKey1Hex,
        publicKeyHex: a.publicKey1Hex,
        multikey: a.multikey1,
        keyId: a.keyId1,
      },
    },
    {
      id: 'key-2',
      description: 'Reference key 2 — the key the rotation introduces.',
      values: {
        seedPhrase: 'dfos-protocol-reference-key-2',
        privateKeyHex: a.privateKey2Hex,
        publicKeyHex: a.publicKey2Hex,
        multikey: a.multikey2,
        keyId: a.keyId2,
      },
    },
    {
      id: 'key-3',
      description:
        'Reference key 3 — a separate identity, the audience of both credential vectors.',
      values: {
        seedPhrase: 'dfos-protocol-reference-key-3',
        privateKeyHex: toHex(keypair3.privateKey),
        publicKeyHex: toHex(keypair3.publicKey),
        multikey: multikey3,
        keyId: keyId3,
        did: identity3.did,
      },
    },
    {
      id: 'identity-genesis',
      description:
        'Identity chain genesis (create, signed by key 1). Carries the canonical dag-cbor bytes, the CID bytes, the SHA-256 of those bytes, and the DID derived from them.',
      values: {
        jws: a.genesisJws,
        payload: a.genesisOp,
        cborHex: a.genesisCborHex,
        cidBytesHex: a.genesisCidBytesHex,
        cid: a.genesisCID,
        didHashHex: toHex(
          new Uint8Array(
            await crypto.subtle.digest('SHA-256', Buffer.from(a.genesisCidBytesHex, 'hex')),
          ),
        ),
        did: a.did,
        kid: a.keyId1,
        typ: 'did:dfos:identity-op',
      },
    },
    {
      id: 'identity-rotation',
      description:
        'Identity chain update (key rotation to key 2, operation signed by key 1). Carries the possession proof.',
      values: {
        jws: a.updateJws,
        cid: a.updateCID,
        kid: `${a.did}#${a.keyId1}`,
        previousOperationCID: a.genesisCID,
      },
    },
    {
      id: 'key-proof',
      description:
        'The possession proof the rotation carries: a did:dfos:key-add envelope signed by key 2, whose payload is closed to exactly seven members in one order.',
      values: {
        jws: a.keyProof,
        typ: KEY_ADD_JWS_TYP,
        canonicalPayload: a.keyProofCanonical,
        members: Object.keys(a.keyProofPayload),
        roleSet: a.keyProofPayload.roleSet,
        publicKeyMultibase: a.keyProofPayload.publicKeyMultibase,
        prevCID: a.keyProofPayload.prevCID,
        did: a.keyProofPayload.did,
      },
    },
    {
      id: 'identity-delete',
      description: 'Identity chain delete (signed by key 2), parented on the rotation.',
      values: { jws: a.deleteJws, cid: a.deleteCID, previousOperationCID: a.updateCID },
    },
    {
      id: 'identity-restore',
      description: 'Identity chain restore (signed by key 2), parented on the delete.',
      values: { jws: a.restoreJws, cid: a.restoreCID, previousOperationCID: a.deleteCID },
    },
    {
      id: 'document',
      description:
        'The content document the create operation commits to. Encode this map as canonical dag-cbor and the CID must come out byte-identical.',
      values: { value: a.contentCreateDocument, cid: a.documentCID },
    },
    {
      id: 'document-updated',
      description: 'The edited document the content update operation commits to.',
      values: { value: a.contentUpdateDocument, cid: a.documentCID2 },
    },
    {
      id: 'content-create',
      description: 'Content chain create (signed by key 2), committing to the document CID.',
      values: {
        jws: a.contentCreateJws,
        cid: a.contentCreateCID,
        kid: `${a.did}#${a.keyId2}`,
        typ: 'did:dfos:content-op',
        documentCID: a.documentCID,
      },
    },
    {
      id: 'content-update',
      description: 'Content chain update (signed by key 2), rebasing on the create.',
      values: {
        jws: a.contentUpdateJws,
        cid: a.contentUpdateCID,
        documentCID: a.documentCID2,
        baseDocumentCID: a.documentCID,
      },
    },
    {
      id: 'content-chain',
      description: 'The verified two-operation content chain: its id, genesis CID, and head CID.',
      values: {
        contentId: a.contentId,
        genesisCID: a.contentGenesisCID,
        headCID: a.contentHeadCID,
      },
    },
    {
      id: 'services-genesis',
      description:
        'An identity create whose payload carries a full-state services discovery array (relay locator + content/artifact anchors). Re-encoding the decoded payload must re-derive this CID and DID.',
      values: {
        jws: servicesGenesisJws,
        payload: servicesGenesisOp,
        cid: servicesGenesisCID,
        did: servicesIdentity.did,
        kid: a.keyId1,
        typ: 'did:dfos:identity-op',
      },
    },
    {
      id: 'credential-write',
      description: 'A DFOS credential granting broad chain write, issued by key 1 to key 3’s DID.',
      values: {
        jws: writeCredentialJws,
        cid: decodeParts(writeCredentialJws).header.cid,
        kid: `${a.did}#${a.keyId1}`,
        typ: 'did:dfos:credential',
        iss: a.did,
        aud: identity3.did,
        resource: 'chain:*',
        action: 'write',
      },
    },
    {
      id: 'credential-read',
      description: 'A DFOS credential granting broad chain read, issued by key 1 to key 3’s DID.',
      values: {
        jws: readCredentialJws,
        cid: decodeParts(readCredentialJws).header.cid,
        kid: `${a.did}#${a.keyId1}`,
        typ: 'did:dfos:credential',
        iss: a.did,
        aud: identity3.did,
        resource: 'chain:*',
        action: 'read',
      },
    },
    {
      id: 'jwt',
      description: 'An EdDSA device-auth JWT signed by key 2.',
      values: { token: a.jwt, iss: 'dfos', sub: a.did, aud: 'dfos-api' },
    },
    {
      id: 'number-integer',
      description:
        'dag-cbor number determinism: whole numbers MUST encode as CBOR integers. floatCborHex/floatCid are the encoding a conforming encoder must never emit.',
      values: {
        value: integerValue,
        cborHex: toHex(integerBlock.bytes),
        cid: integerBlock.cid.toString(),
        floatCborHex: toHex(floatVersionCbor),
        floatCid: await cidOverBytes(floatVersionCbor),
      },
    },
    {
      id: 'number-max-safe',
      description: 'WP-0 number policy: 2^53-1 is the largest accepted integer.',
      values: { value: maxSafeValue, cid: maxSafeBlock.cid.toString() },
    },
    {
      id: 'number-null-vector',
      description: 'WP-0 number policy: nulls and empty arrays encode without normalization.',
      values: { value: nullValue, cid: nullBlock.cid.toString() },
    },
    {
      id: 'reject-corpus',
      description:
        'Nine tokens every conformant verifier MUST reject, each isolating one profile or signature gate. The base vector is a valid JWS signed by key 1; publicKeyHex is the key to verify against.',
      values: { publicKeyHex: a.publicKey1Hex, tokens: rejectVectors },
    },
  ];

  return {
    version: 1,
    description:
      'Shared deterministic reference vectors for the DFOS protocol. Generated from the fixed seeds by packages/dfos-protocol/tests/protocol-reference.spec.ts and consumed by every protocol-verify suite — do not hand-edit.',
    generator: 'packages/dfos-protocol/tests/protocol-reference.spec.ts',
    vectors,
  };
}

const VECTORS_PATH = path.resolve(__dirname, '../../protocol-verify/vectors.json');

const serializeVectors = (doc: VectorsDocument) => `${JSON.stringify(doc, null, 2)}\n`;

// Resolve the spec + fixtures relative to this test file, not the cwd, so the
// drift guard is robust to where vitest is invoked from.
const SPEC_PATH = path.resolve(__dirname, '../../../specs/PROTOCOL.md');
const EXAMPLES_DIR = path.resolve(__dirname, '../examples');

const readExample = (name: string) =>
  JSON.parse(fs.readFileSync(path.join(EXAMPLES_DIR, name), 'utf-8'));

describe('protocol reference artifacts', () => {
  it('generates all reference data', async () => {
    const a = await generateReferenceArtifacts();

    DIV('STEP 1: Deterministic Ed25519 Keypairs');
    console.log('=== Key 1 (genesis controller) ===');
    console.log('Private key:', a.privateKey1Hex);
    console.log('Public key: ', a.publicKey1Hex);
    console.log('Multikey:   ', a.multikey1);
    console.log('Key ID:     ', a.keyId1);
    console.log('(derived:    key_ + customAlpha(SHA-256(publicKey)))');

    console.log('\n=== Key 2 (rotated controller) ===');
    console.log('Private key:', a.privateKey2Hex);
    console.log('Public key: ', a.publicKey2Hex);
    console.log('Multikey:   ', a.multikey2);
    console.log('Key ID:     ', a.keyId2);

    const { base58btc } = await import('multiformats/bases/base58');
    const decoded1 = decodeMultikey(a.multikey1);
    const multikeyRawBytes = base58btc.decode(a.multikey1);
    console.log('\n=== Multikey encoding detail ===');
    console.log('Raw bytes (hex):     ', hex(multikeyRawBytes));
    console.log(
      'Prefix bytes:        ',
      hex(multikeyRawBytes.slice(0, 2)),
      '(varint of 0xed = ed25519-pub multicodec)',
    );
    console.log('Key bytes:           ', hex(multikeyRawBytes.slice(2)));
    console.log('Decoded codec:       ', '0x' + decoded1.codec.toString(16));
    console.log('Decoded bytes match: ', hex(decoded1.keyBytes) === a.publicKey1Hex);

    DIV('STEP 2: Identity Chain — Create (Genesis)');
    console.log('--- Operation (unsigned) ---');
    console.log(JSON.stringify(a.genesisOp, null, 2));
    console.log('\n--- JWS Header ---');
    console.log(JSON.stringify(a.genesisHeader, null, 2));
    console.log('\n--- JWS Signature (hex) ---');
    console.log(a.genesisSignatureHex);
    console.log('\n--- JWS Compact Token ---');
    console.log(a.genesisJws);
    console.log('\nOperation CID:', a.genesisCID);
    console.log('\n--- dag-cbor encoding detail ---');
    console.log('CBOR bytes (hex):', a.genesisCborHex);
    console.log('CID bytes (hex): ', a.genesisCidBytesHex);

    DIV('STEP 3: Identity Verification + DID Derivation');
    console.log('Derived DID:  ', a.did);

    DIV('STEP 4: Identity Chain — Update (Key Rotation)');
    console.log('--- Operation (unsigned) ---');
    console.log(JSON.stringify(a.updateOp, null, 2));
    console.log('\n--- JWS Header ---');
    console.log(JSON.stringify(a.updateHeader, null, 2));
    console.log('\n--- JWS Signature (hex) ---');
    console.log(a.updateSignatureHex);
    console.log('\n--- JWS Compact Token ---');
    console.log(a.updateJws);
    console.log('\nOperation CID:', a.updateCID);

    DIV('STEP 4A: The Key Proof the Rotation Carries');
    console.log('--- Payload (decoded) ---');
    console.log(JSON.stringify(a.keyProofPayload, null, 2));
    console.log('\n--- Canonical signing input (the exact payload octets) ---');
    console.log(a.keyProofCanonical);
    console.log('\n--- JWS Header ---');
    console.log(JSON.stringify(a.keyProofHeader, null, 2));
    console.log('\n--- JWS Signature (hex) ---');
    console.log(a.keyProofSignatureHex);
    console.log('\n--- JWS Compact Token ---');
    console.log(a.keyProof);

    DIV('STEP 4B: Identity Chain — Delete + Restore');
    console.log('--- Delete Operation ---');
    console.log(JSON.stringify(a.deleteOp, null, 2));
    console.log('\n--- Delete JWS Header ---');
    console.log(JSON.stringify(a.deleteHeader, null, 2));
    console.log('\n--- Delete JWS Signature (hex) ---');
    console.log(a.deleteSignatureHex);
    console.log('\n--- Delete JWS Compact Token ---');
    console.log(a.deleteJws);
    console.log('\nDelete operation CID:', a.deleteCID);
    console.log('\n--- Restore Operation ---');
    console.log(JSON.stringify(a.restoreOp, null, 2));
    console.log('\n--- Restore JWS Header ---');
    console.log(JSON.stringify(a.restoreHeader, null, 2));
    console.log('\n--- Restore JWS Signature (hex) ---');
    console.log(a.restoreSignatureHex);
    console.log('\n--- Restore JWS Compact Token ---');
    console.log(a.restoreJws);
    console.log('\nRestore operation CID:', a.restoreCID);

    DIV('STEP 5: Content Chain — Document + Create');
    console.log('Document CID:', a.documentCID);
    console.log('\n--- Content Create JWS Header ---');
    console.log(JSON.stringify(a.contentCreateHeader, null, 2));
    console.log('\n--- Content Create JWS Signature (hex) ---');
    console.log(a.contentCreateSignatureHex);
    console.log('\n--- Content Create JWS Compact Token ---');
    console.log(a.contentCreateJws);
    console.log('\nContent operation CID:', a.contentCreateCID);

    DIV('STEP 6: Content Chain — Update');
    console.log('Content update CID:', a.contentUpdateCID);
    console.log('Document CID (edited):', a.documentCID2);
    console.log('\n--- Verified Content Chain ---');
    console.log('Content ID:       ', a.contentId);
    console.log('Genesis CID:     ', a.contentGenesisCID);
    console.log('Head CID:        ', a.contentHeadCID);

    DIV('STEP 7: EdDSA JWT');
    console.log('--- JWT Compact Token ---');
    console.log(a.jwt);
    console.log('\nJWT verified, subject:', a.jwtSubject);

    DIV('SUMMARY');
    console.log('IDENTITY CHAIN');
    console.log('  DID:             ', a.did);
    console.log('  Key 1 (genesis): ', a.keyId1, '→', a.multikey1);
    console.log('  Key 2 (rotated): ', a.keyId2, '→', a.multikey2);
    console.log('  [0] create  CID: ', a.genesisCID);
    console.log('  [1] update  CID: ', a.updateCID);
    console.log('  [2] delete  CID: ', a.deleteCID);
    console.log('  [3] restore CID: ', a.restoreCID);
    console.log('\nCONTENT CHAIN');
    console.log('  Content ID:       ', a.contentId);
    console.log('  Genesis CID:     ', a.contentGenesisCID);
    console.log('  Head CID:        ', a.contentHeadCID);
    console.log('  [0] create  CID: ', a.contentCreateCID);
    console.log('      documentCID: ', a.documentCID);
    console.log('  [1] update  CID: ', a.contentUpdateCID);
    console.log('      documentCID: ', a.documentCID2);
  });

  /**
   * DRIFT GUARD. The freshly-generated artifacts MUST be byte-identical to the
   * golden values inlined in specs/PROTOCOL.md and the examples/ fixtures. A
   * corrupted spec vector (like #57) fails here.
   */
  it('matches the golden values in PROTOCOL.md and examples/', async () => {
    const a = await generateReferenceArtifacts();
    const spec = fs.readFileSync(SPEC_PATH, 'utf-8');

    // Helper: assert a generated value appears verbatim somewhere in PROTOCOL.md.
    // This is what catches a one-character corruption of an inlined JWS/CID/key.
    const expectInSpec = (label: string, value: string) => {
      expect(value.length, `${label} must be a non-empty generated value`).toBeGreaterThan(0);
      expect(
        spec.includes(value),
        `${label} (generated) was NOT found byte-for-byte in specs/PROTOCOL.md — ` +
          `the spec vector has drifted from the implementation. Value: ${value}`,
      ).toBe(true);
    };

    // --- keys / ids / DID (all present in PROTOCOL.md reference test vectors) ---
    expectInSpec('privateKey1', a.privateKey1Hex);
    expectInSpec('publicKey1', a.publicKey1Hex);
    expectInSpec('multikey1', a.multikey1);
    expectInSpec('keyId1', a.keyId1);
    expectInSpec('privateKey2', a.privateKey2Hex);
    expectInSpec('publicKey2', a.publicKey2Hex);
    expectInSpec('multikey2', a.multikey2);
    expectInSpec('keyId2', a.keyId2);
    expectInSpec('DID', a.did);

    // Sanity-pin the literal expected values so a *coordinated* drift (spec AND
    // generator both changed) still trips the guard.
    expect(a.multikey1).toBe('z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb');
    expect(a.multikey2).toBe('z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK');
    expect(a.keyId1).toBe('key_r9ev34fvc23z999veaaft83nn29zvhe');
    expect(a.keyId2).toBe('key_ez9a874tckr3dv933d3ckdn7z6zrct8');
    expect(a.privateKey1Hex).toBe(
      '132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac',
    );
    expect(a.privateKey2Hex).toBe(
      '384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8',
    );
    expect(a.did).toBe('did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr');

    // --- identity chain: the inlined JWS tokens + their CIDs + signatures ---
    // The genesis JWS is the exact token #57 corrupted (one base64url char). This
    // assertion is the regression guard.
    expectInSpec('genesis JWS', a.genesisJws);
    expectInSpec('genesis CID', a.genesisCID);
    expectInSpec('genesis signature (hex)', a.genesisSignatureHex);
    // genesis CID bytes hex is inlined on a single line in PROTOCOL.md's DID
    // derivation worked example, so it is substring-checkable.
    expectInSpec('genesis CID bytes (hex)', a.genesisCidBytesHex);
    expectInSpec('rotation JWS', a.updateJws);
    expectInSpec('rotation CID', a.updateCID);
    expectInSpec('rotation signature (hex)', a.updateSignatureHex);
    // The possession proof the rotation carries, and its canonical payload bytes.
    expectInSpec('rotation key proof', a.keyProof);
    expectInSpec('rotation key proof canonical payload', a.keyProofCanonical);
    expectInSpec('rotation key proof signature (hex)', a.keyProofSignatureHex);
    expectInSpec('delete JWS', a.deleteJws);
    expectInSpec('delete CID', a.deleteCID);
    expectInSpec('delete signature (hex)', a.deleteSignatureHex);
    expectInSpec('restore JWS', a.restoreJws);
    expectInSpec('restore CID', a.restoreCID);
    expectInSpec('restore signature (hex)', a.restoreSignatureHex);

    expect(a.genesisCID).toBe('bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne');
    expect(a.updateCID).toBe('bafyreiarc7mv6fvhaoe2mmk4ujpskgqpesv66pzd5juqlg5bzmridikkqy');
    // The 468-byte CBOR blob is line-wrapped in PROTOCOL.md (so not substring-
    // checkable as one contiguous string); pin it as a literal instead so a
    // generator-side change to canonical encoding still trips the guard.
    expect(a.genesisCborHex).toBe(
      'a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62',
    );

    // --- content chain: document CIDs, content-op JWS + CIDs, content id ---
    expectInSpec('document CID', a.documentCID);
    expectInSpec('content create JWS', a.contentCreateJws);
    expectInSpec('content create CID', a.contentCreateCID);
    expectInSpec('content create signature (hex)', a.contentCreateSignatureHex);
    expectInSpec('updated document CID', a.documentCID2);
    expectInSpec('content update CID', a.contentUpdateCID);
    expectInSpec('content id', a.contentId);

    expect(a.documentCID).toBe('bafyreie6xfkrtwax2dq5gdw3rpsurz2glsduxycfhk7jjllewiwivkkafu');
    expect(a.documentCID2).toBe('bafyreiaoinzo2ai4hx56b7244zahnfqmgurcd3rppqbawhv32xzlvct5m4');
    expect(a.contentCreateCID).toBe('bafyreibs3vlvainfjfuet6x4uds3pivbmbohy7f64iegbuw3gpsuqtma6i');
    expect(a.contentUpdateCID).toBe('bafyreied5cjgjjt2pdz52k6pgipcjg3i4xl7txbrbdedscejvqhtgltxdi');
    expect(a.contentId).toBe('8n8fnzhrrefkrde6h72kfvff43r8c63');

    // --- cross-check the examples/ fixtures (a second golden source) ---
    // identity-genesis.json: chain[0] is the genesis JWS, expected pins DID/keys.
    const genesisFixture = readExample('identity-genesis.json');
    expect(genesisFixture.chain[0], 'examples/identity-genesis.json chain[0] drift').toBe(
      a.genesisJws,
    );
    expect(genesisFixture.expected.did).toBe(a.did);
    expect(genesisFixture.expected.controllerKeys[0].id).toBe(a.keyId1);
    expect(genesisFixture.expected.controllerKeys[0].publicKeyMultibase).toBe(a.multikey1);

    // identity-rotation.json: chain = [genesis, update], expected pins rotated controller.
    const rotationFixture = readExample('identity-rotation.json');
    expect(rotationFixture.chain[0], 'examples/identity-rotation.json chain[0] drift').toBe(
      a.genesisJws,
    );
    expect(rotationFixture.chain[1], 'examples/identity-rotation.json chain[1] drift').toBe(
      a.updateJws,
    );
    expect(rotationFixture.expected.did).toBe(a.did);
    expect(rotationFixture.expected.controllerKeys[0].id).toBe(a.keyId2);
    expect(rotationFixture.expected.controllerKeys[0].publicKeyMultibase).toBe(a.multikey2);

    // identity-restore.json extends the published rotation vector additively.
    const restoreFixture = readExample('identity-restore.json');
    expect(restoreFixture.chain).toEqual([a.genesisJws, a.updateJws, a.deleteJws, a.restoreJws]);
    expect(restoreFixture.expected.did).toBe(a.did);
    expect(restoreFixture.expected.isDeleted).toBe(false);
    expect(restoreFixture.expected.controllerKeys[0].id).toBe(a.keyId2);

    // content-lifecycle.json: chain = [create, update], expected pins content state.
    const contentFixture = readExample('content-lifecycle.json');
    expect(contentFixture.chain[0], 'examples/content-lifecycle.json chain[0] drift').toBe(
      a.contentCreateJws,
    );
    expect(contentFixture.chain[1], 'examples/content-lifecycle.json chain[1] drift').toBe(
      a.contentUpdateJws,
    );
    expect(contentFixture.expected.contentId).toBe(a.contentId);
    expect(contentFixture.expected.currentDocumentCID).toBe(a.documentCID2);
    expect(contentFixture.signerPublicKey).toBe(a.multikey2);
  });

  /**
   * ARTIFACT GUARD. packages/protocol-verify/vectors.json is what all five
   * standalone suites and the Go twin's reference tests read. It must be
   * byte-identical to a fresh generation from the seeds, or a suite is
   * asserting a value the reference implementation no longer produces.
   */
  it('matches packages/protocol-verify/vectors.json byte-for-byte', async () => {
    const a = await generateReferenceArtifacts();
    const generated = serializeVectors(await generateSharedVectors(a));

    if (process.env.UPDATE_VECTORS === '1') {
      fs.writeFileSync(VECTORS_PATH, generated, 'utf-8');
      return;
    }

    const onDisk = fs.readFileSync(VECTORS_PATH, 'utf-8');
    expect(
      onDisk,
      'packages/protocol-verify/vectors.json has drifted from the generator — ' +
        'regenerate with UPDATE_VECTORS=1 and re-read the diff before accepting it',
    ).toBe(generated);
  });
});
