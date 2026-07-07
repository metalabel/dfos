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
import {
  base64urlDecode,
  createJwt,
  dagCborCanonicalEncode,
  generateId,
  importEd25519Keypair,
  signPayloadEd25519,
  verifyJwt,
} from '../src/crypto';

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
  // content chain
  documentCID: string;
  contentCreateOp: ContentOperation;
  contentCreateJws: string;
  contentCreateCID: string;
  contentCreateSignatureHex: string;
  contentCreateHeader: Record<string, unknown>;
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
  const updateOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: genesisCID,
    authKeys: [key2],
    assertKeys: [key2],
    controllerKeys: [key2],
    createdAt: '2026-03-07T00:01:00.000Z',
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

  // ----------------------------------------------------------------
  // Content chain: document + create
  // ----------------------------------------------------------------
  const signer2 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair2.privateKey);
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
    documentCID,
    contentCreateOp: createContentOp,
    contentCreateJws,
    contentCreateCID,
    contentCreateSignatureHex: ccParts.signatureHex,
    contentCreateHeader: ccParts.header,
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
    console.log('--- JWS Header ---');
    console.log(JSON.stringify(a.updateHeader, null, 2));
    console.log('\n--- JWS Signature (hex) ---');
    console.log(a.updateSignatureHex);
    console.log('\n--- JWS Compact Token ---');
    console.log(a.updateJws);
    console.log('\nOperation CID:', a.updateCID);

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

    expect(a.genesisCID).toBe('bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne');
    expect(a.updateCID).toBe('bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei');
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
});
