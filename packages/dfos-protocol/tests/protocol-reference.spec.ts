/**
 * Protocol reference — generates deterministic artifacts for the spec doc
 *
 * Uses fixed seeds so output is reproducible. Every value printed here
 * can be independently verified by any Ed25519 + dag-cbor implementation.
 */

import { describe, it } from 'vitest';
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
  createJws,
  createJwt,
  dagCborCanonicalEncode,
  generateId,
  importEd25519Keypair,
  signPayloadEd25519,
  verifyJws,
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

describe('protocol reference artifacts', () => {
  it('generates all reference data', async () => {
    // ================================================================
    // DETERMINISTIC KEY GENERATION
    // Use sha256 of known strings as private keys for reproducibility
    // ================================================================
    DIV('STEP 1: Deterministic Ed25519 Keypairs');

    // Use fixed 32-byte private keys for reproducibility
    const seed1 = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode('dfos-protocol-reference-key-1'),
      ),
    );
    const keypair1 = importEd25519Keypair(seed1);
    const multikey1 = encodeEd25519Multikey(keypair1.publicKey);
    // Key ID derived from public key hash — convention, not requirement
    const keyId1 = generateId('key', { seed: keypair1.publicKey });

    console.log('=== Key 1 (genesis controller) ===');
    console.log('Private key:', hex(keypair1.privateKey));
    console.log('Public key: ', hex(keypair1.publicKey));
    console.log('Multikey:   ', multikey1);
    console.log('Key ID:     ', keyId1);
    console.log('(derived:    key_ + customAlpha(SHA-256(publicKey)))');

    const seed2 = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode('dfos-protocol-reference-key-2'),
      ),
    );
    const keypair2 = importEd25519Keypair(seed2);
    const multikey2 = encodeEd25519Multikey(keypair2.publicKey);
    const keyId2 = generateId('key', { seed: keypair2.publicKey });

    console.log('\n=== Key 2 (rotated controller) ===');
    console.log('Private key:', hex(keypair2.privateKey));
    console.log('Public key: ', hex(keypair2.publicKey));
    console.log('Multikey:   ', multikey2);
    console.log('Key ID:     ', keyId2);

    // Multikey decode verification — show intermediate bytes
    const { base58btc } = await import('multiformats/bases/base58');
    const decoded1 = decodeMultikey(multikey1);
    const multikeyRawBytes = base58btc.decode(multikey1);
    console.log('\n=== Multikey encoding detail ===');
    console.log('Raw bytes (hex):     ', hex(multikeyRawBytes));
    console.log(
      'Prefix bytes:        ',
      hex(multikeyRawBytes.slice(0, 2)),
      '(varint of 0xed = ed25519-pub multicodec)',
    );
    console.log('Key bytes:           ', hex(multikeyRawBytes.slice(2)));
    console.log('Decoded codec:       ', '0x' + decoded1.codec.toString(16));
    console.log('Decoded bytes match: ', hex(decoded1.keyBytes) === hex(keypair1.publicKey));

    // ================================================================
    // IDENTITY CHAIN: CREATE (GENESIS)
    // ================================================================
    DIV('STEP 2: Identity Chain — Create (Genesis)');

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

    console.log('--- Operation (unsigned) ---');
    console.log(JSON.stringify(genesisOp, null, 2));

    const genParts = decodeParts(genesisJws);
    console.log('\n--- JWS Header ---');
    console.log(JSON.stringify(genParts.header, null, 2));
    console.log('\n--- JWS Payload ---');
    console.log(JSON.stringify(genParts.payload, null, 2));
    console.log('\n--- JWS Signature (hex) ---');
    console.log(genParts.signatureHex);
    console.log('\n--- JWS Compact Token ---');
    console.log(genesisJws);
    console.log('\nOperation CID:', genesisCID);

    // Show dag-cbor intermediate bytes for CID derivation
    const genesisEncoded = await dagCborCanonicalEncode(genesisOp);
    console.log('\n--- dag-cbor encoding detail ---');
    console.log('CBOR bytes (hex):', hex(genesisEncoded.bytes));
    console.log('CBOR length:     ', genesisEncoded.bytes.length, 'bytes');
    console.log('CID bytes (hex): ', hex(genesisEncoded.cid.bytes));
    console.log('CID string:      ', genesisEncoded.cid.toString());

    // Show DID derivation intermediate
    const didHash = new Uint8Array(await crypto.subtle.digest('SHA-256', genesisEncoded.cid.bytes));
    console.log('\n--- DID derivation detail ---');
    console.log('SHA-256(CID bytes):', hex(didHash));
    console.log('First 22 bytes:   ', hex(didHash.slice(0, 22)));
    const alphabet = '2346789acdefhknrtvz';
    const didSuffix = Array.from(didHash.slice(0, 22))
      .map((b) => alphabet[b % 19])
      .join('');
    console.log('ID encoding:      ', didSuffix);

    // ================================================================
    // IDENTITY CHAIN: VERIFY + DID DERIVATION
    // ================================================================
    DIV('STEP 3: Identity Verification + DID Derivation');

    const identity = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [genesisJws],
    });

    console.log('Derived DID:  ', identity.did);

    console.log('Is deleted:   ', identity.isDeleted);
    console.log('Controller:   ', identity.controllerKeys[0]?.id);

    // ================================================================
    // IDENTITY CHAIN: UPDATE (KEY ROTATION)
    // ================================================================
    DIV('STEP 4: Identity Chain — Update (Key Rotation)');

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
      identityDID: identity.did,
    });

    const updParts = decodeParts(updateJws);
    console.log('--- JWS Header ---');
    console.log(JSON.stringify(updParts.header, null, 2));
    console.log('\n--- JWS Payload ---');
    console.log(JSON.stringify(updParts.payload, null, 2));
    console.log('\n--- JWS Signature (hex) ---');
    console.log(updParts.signatureHex);
    console.log('\n--- JWS Compact Token ---');
    console.log(updateJws);
    console.log('\nOperation CID:', updateCID);

    // Verify full 2-op log
    const identity2 = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [genesisJws, updateJws],
    });
    console.log('\nPost-rotation DID (unchanged):', identity2.did);
    console.log('New controller:', identity2.controllerKeys[0]?.id);

    // ================================================================
    // CONTENT CHAIN: DOCUMENT + CREATE
    // ================================================================
    DIV('STEP 5: Content Chain — Document + Create');

    const signer2 = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair2.privateKey);
    const kid2 = `${identity2.did}#${keyId2}`;

    // Create a document (application layer — flat content object, no envelope)
    const document = {
      $schema: 'https://schemas.dfos.com/post/v1',
      format: 'short-post',
      title: 'Hello World',
      body: 'First post on the protocol.',
      createdByDID: identity2.did,
    };

    const docBlock = await dagCborCanonicalEncode(document);
    const documentCID = docBlock.cid.toString();

    console.log('--- Document (application layer) ---');
    console.log(JSON.stringify(document, null, 2));
    console.log('\nDocument CID:', documentCID);

    // Create content chain operation
    const createContentOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: identity2.did,
      documentCID,
      baseDocumentCID: null,
      createdAt: '2026-03-07T00:02:00.000Z',
      note: null,
    };

    const { jwsToken: contentCreateJws, operationCID: contentCreateCID } =
      await signContentOperation({
        operation: createContentOp,
        signer: signer2,
        kid: kid2,
      });

    const ccParts = decodeParts(contentCreateJws);
    console.log('\n--- Content Create JWS Header ---');
    console.log(JSON.stringify(ccParts.header, null, 2));
    console.log('\n--- Content Create JWS Payload ---');
    console.log(JSON.stringify(ccParts.payload, null, 2));
    console.log('\n--- Content Create JWS Signature (hex) ---');
    console.log(ccParts.signatureHex);
    console.log('\n--- Content Create JWS Compact Token ---');
    console.log(contentCreateJws);
    console.log('\nContent operation CID:', contentCreateCID);

    // ================================================================
    // CONTENT CHAIN: UPDATE
    // ================================================================
    DIV('STEP 6: Content Chain — Update');

    const document2 = {
      $schema: 'https://schemas.dfos.com/post/v1',
      format: 'short-post',
      title: 'Hello World (edited)',
      body: 'Updated content.',
      createdByDID: identity2.did,
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
      note: 'edited title and body',
    };

    const { jwsToken: contentUpdateJws, operationCID: contentUpdateCID } =
      await signContentOperation({
        operation: updateContentOp,
        signer: signer2,
        kid: kid2,
      });

    const cuParts = decodeParts(contentUpdateJws);
    console.log('--- Content Update JWS Header ---');
    console.log(JSON.stringify(cuParts.header, null, 2));
    console.log('\n--- Content Update JWS Payload ---');
    console.log(JSON.stringify(cuParts.payload, null, 2));
    console.log('\nContent update CID:', contentUpdateCID);
    console.log('Document CID (edited):', documentCID2);

    // Verify the full content chain
    const contentChain = await verifyContentChain({
      log: [contentCreateJws, contentUpdateJws],
      resolveKey: async () => keypair2.publicKey,
    });

    console.log('\n--- Verified Content Chain ---');
    console.log('Content ID:       ', contentChain.contentId);
    console.log('Genesis CID:     ', contentChain.genesisCID);
    console.log('Head CID:        ', contentChain.headCID);
    console.log('Current doc CID: ', contentChain.currentDocumentCID);
    console.log('Is deleted:      ', contentChain.isDeleted);
    console.log('Chain length:    ', contentChain.length);

    // ================================================================
    // JWT (device auth)
    // ================================================================
    DIV('STEP 7: EdDSA JWT');

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

    const jwtParts = decodeParts(jwt);
    console.log('--- JWT Header ---');
    console.log(JSON.stringify(jwtParts.header, null, 2));
    console.log('\n--- JWT Payload ---');
    console.log(JSON.stringify(jwtParts.payload, null, 2));
    console.log('\n--- JWT Compact Token ---');
    console.log(jwt);

    const jwtResult = verifyJwt({
      token: jwt,
      publicKey: keypair2.publicKey,
      issuer: 'dfos',
      audience: 'dfos-api',
      currentTime: 1772899200,
    });
    console.log('\nJWT verified, subject:', jwtResult.payload.sub);

    // ================================================================
    // FULL SUMMARY
    // ================================================================
    DIV('SUMMARY');

    console.log('IDENTITY CHAIN');
    console.log('  DID:             ', identity2.did);
    console.log('  Key 1 (genesis): ', keyId1, '→', multikey1);
    console.log('  Key 2 (rotated): ', keyId2, '→', multikey2);
    console.log('  [0] create  CID: ', genesisCID);
    console.log('      kid:         ', genParts.header.kid, '(bare)');
    console.log('  [1] update  CID: ', updateCID);
    console.log('      kid:         ', updParts.header.kid, '(DID URL)');

    console.log('\nCONTENT CHAIN');
    console.log('  Content ID:       ', contentChain.contentId);
    console.log('  Genesis CID:     ', contentChain.genesisCID);
    console.log('  Head CID:        ', contentChain.headCID);
    console.log('  [0] create  CID: ', contentCreateCID);
    console.log('      documentCID: ', documentCID);
    console.log('      kid:         ', ccParts.header.kid);
    console.log('  [1] update  CID: ', contentUpdateCID);
    console.log('      documentCID: ', documentCID2);
    console.log('      kid:         ', cuParts.header.kid);

    console.log('\nJWT');
    console.log('  alg:', jwtParts.header.alg);
    console.log('  sub:', jwtResult.payload.sub);
    console.log('  kid:', jwtParts.header.kid);
  });
});
