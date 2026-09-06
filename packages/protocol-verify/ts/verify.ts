/**
 * DFOS Protocol — Independent verification in TypeScript
 *
 * Verifies all deterministic reference artifacts from the protocol specification.
 * Uses only direct crypto dependencies — NOT @metalabel/dfos-protocol.
 *
 * Run: npx tsx verify.ts
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as dagCbor from '@ipld/dag-cbor';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { base32 } from 'multiformats/bases/base32';
import { base58btc } from 'multiformats/bases/base58';

// =============================================================================
// Shared reference vectors
// =============================================================================
//
// Every expected value below is read from ../vectors.json — the one artifact
// all five suites share, generated from the protocol's fixed seeds by
// packages/dfos-protocol/tests/protocol-reference.spec.ts, which asserts the
// checked-in file is byte-identical to a fresh generation.
//
// Reading a JSON fixture is not a library import. This suite still uses only
// the language's native Ed25519, dag-cbor and SHA-256, and a third party can
// run it with nothing but this file and vectors.json.

interface Vector {
  id: string;
  description: string;
  values: Record<string, unknown>;
}

interface VectorsFile {
  version: number;
  description: string;
  generator: string;
  vectors: Vector[];
}

const VECTORS_PATH = fileURLToPath(new URL('../vectors.json', import.meta.url));
const VECTORS_BY_ID = new Map<string, Record<string, unknown>>(
  (JSON.parse(readFileSync(VECTORS_PATH, 'utf-8')) as VectorsFile).vectors.map((v) => [
    v.id,
    v.values,
  ]),
);

/** All values of one vector, by id. */
function vectorValues(id: string): Record<string, unknown> {
  const values = VECTORS_BY_ID.get(id);
  if (!values) throw new Error(`vectors.json has no vector "${id}"`);
  return values;
}

/** One string field of one vector. */
function vec(id: string, field: string): string {
  const value = vectorValues(id)[field];
  if (typeof value !== 'string') throw new Error(`vectors.json ${id}.${field} is not a string`);
  return value;
}

/** One object field of one vector (a document, an operation payload, a token map). */
function vecObject(id: string, field: string): Record<string, unknown> {
  const value = vectorValues(id)[field];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`vectors.json ${id}.${field} is not an object`);
  }
  return value as Record<string, unknown>;
}

/** One string-array field of one vector. */
function vecStrings(id: string, field: string): string[] {
  const value = vectorValues(id)[field];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`vectors.json ${id}.${field} is not a string array`);
  }
  return value as string[];
}

// =============================================================================
// Constants from the reference spec
// =============================================================================

const ALPHABET = '2346789acdefhknrtvz';
const ID_LENGTH = 31;

const GENESIS_JWS = vec('identity-genesis', 'jws');
const ROTATION_JWS = vec('identity-rotation', 'jws');
const DELETE_JWS = vec('identity-delete', 'jws');
const RESTORE_JWS = vec('identity-restore', 'jws');
const CONTENT_CREATE_JWS = vec('content-create', 'jws');
const JWT_TOKEN = vec('jwt', 'token');
const BROAD_WRITE_VC = vec('credential-write', 'jws');
const READ_VC = vec('credential-read', 'jws');

// Services genesis: an identity create whose payload carries a full-state
// services discovery array (relay locator + content/artifact anchors). The
// services fields ride along in the payload map — no services-validation logic
// is required here; the verifier re-derives the operation CID over the decoded
// payload and the services entries participate automatically.
const SERVICES_GENESIS_JWS = vec('services-genesis', 'jws');

const EXPECTED_GENESIS_CID = vec('identity-genesis', 'cid');
const EXPECTED_SERVICES_CID = vec('services-genesis', 'cid');
const EXPECTED_SERVICES_DID = vec('services-genesis', 'did');
const EXPECTED_DID = vec('identity-genesis', 'did');
const EXPECTED_MULTIKEY1 = vec('key-1', 'multikey');
const EXPECTED_MULTIKEY2 = vec('key-2', 'multikey');

// The possession proof the rotation carries. Its payload is CLOSED: exactly
// these seven members, in exactly this order — and the octets below are the only
// serialization those members are ever signed as. The envelope is signed by
// key 2 (the key being introduced) while the operation carrying it is signed by
// key 1.
const KEY_PROOF_MEMBERS = vecStrings('key-proof', 'members');
const KEY_PROOF_ROLE_SET = vec('key-proof', 'roleSet');
const KEY_PROOF_CANONICAL_PAYLOAD = vec('key-proof', 'canonicalPayload');
const EXPECTED_CBOR_HEX = vec('identity-genesis', 'cborHex');
const EXPECTED_CID_HEX = vec('identity-genesis', 'cidBytesHex');

// =============================================================================
// Helpers
// =============================================================================

function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (padded.length % 4)) % 4;
  const b64 = padded + '='.repeat(padding);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexDecode(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function encodeId(hashBytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < ID_LENGTH; i++) {
    result += ALPHABET[hashBytes[i]! % 19];
  }
  return result;
}

function encodeMultikey(pubBytes: Uint8Array): string {
  const raw = new Uint8Array([0xed, 0x01, ...pubBytes]);
  return base58btc.encode(raw);
}

function decodeMultikey(multibase: string): Uint8Array {
  const raw = base58btc.decode(multibase);
  if (raw[0] !== 0xed || raw[1] !== 0x01) {
    throw new Error(`expected ed25519-pub multicodec prefix, got ${hexEncode(raw.slice(0, 2))}`);
  }
  return raw.slice(2);
}

function makeCidBytes(cborBytes: Uint8Array): Uint8Array {
  const digest = sha256(cborBytes);
  // CIDv1: version(0x01) + codec(0x71=dag-cbor) + multihash(0x12=sha256, 0x20=32 bytes, digest)
  return new Uint8Array([0x01, 0x71, 0x12, 0x20, ...digest]);
}

function cidToBase32(cidBytes: Uint8Array): string {
  return base32.encode(cidBytes);
}

// Ed25519 group order L (little-endian 32 bytes) — the canonical S < L bound.
const ED25519_L = new Uint8Array([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]);

// constant-time-ish little-endian compare: returns true iff s < L
function scalarIsCanonical(s: Uint8Array): boolean {
  if (s.length !== 32) return false;
  for (let i = 31; i >= 0; i--) {
    if (s[i]! < ED25519_L[i]!) return true;
    if (s[i]! > ED25519_L[i]!) return false;
  }
  return false; // s === L is non-canonical
}

// DFOS Signature Verification Profile (pragmatic v1) header gates. Applied
// BEFORE any signature check. See PROTOCOL.md "Signature Verification Profile".
function assertJwsProfile(header: Record<string, unknown>): void {
  if (header.alg !== 'EdDSA') throw new Error(`unsupported algorithm: ${String(header.alg)}`);
  if ('crit' in header) throw new Error('crit header is not supported');
  if ('jwk' in header) throw new Error('jwk header is not allowed');
  if ('x5c' in header) throw new Error('x5c header is not allowed');
}

function verifyJws(
  token: string,
  pubKeyBytes: Uint8Array,
): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid JWS');
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64)));

  // profile gates run before any signature work
  assertJwsProfile(header);

  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = b64urlDecode(sigB64);

  // length + canonical-scalar (S < L) gates
  if (signature.length !== 64)
    throw new Error(`signature must be 64 bytes, got ${signature.length}`);
  if (!scalarIsCanonical(signature.slice(32, 64)))
    throw new Error('non-canonical signature scalar (S >= L)');

  const valid = ed25519.verify(signature, signingInput, pubKeyBytes);
  if (!valid) throw new Error('signature verification failed');

  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
  return { header, payload };
}

// =============================================================================
// Test runner
// =============================================================================

let passed = 0;
let failed = 0;

function check(name: string, condition: boolean, detail = '') {
  if (condition) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${detail}`);
  }
}

console.log('='.repeat(70));
console.log('DFOS Protocol — TypeScript Verification (standalone)');
console.log('='.repeat(70));

// --- 1. Deterministic key derivation ---
console.log('\n1. Key Derivation');
const seed1 = sha256(new TextEncoder().encode('dfos-protocol-reference-key-1'));
const pub1 = ed25519.getPublicKey(seed1);
check('Key 1 private', hexEncode(seed1) === vec('key-1', 'privateKeyHex'));
check('Key 1 public', hexEncode(pub1) === vec('key-1', 'publicKeyHex'));

const seed2 = sha256(new TextEncoder().encode('dfos-protocol-reference-key-2'));
const pub2 = ed25519.getPublicKey(seed2);
check('Key 2 private', hexEncode(seed2) === vec('key-2', 'privateKeyHex'));
check('Key 2 public', hexEncode(pub2) === vec('key-2', 'publicKeyHex'));

// --- 2. Multikey encoding ---
console.log('\n2. Multikey Encoding');
const multikey1 = encodeMultikey(pub1);
check('Multikey 1 encode', multikey1 === EXPECTED_MULTIKEY1, `got ${multikey1}`);
const decodedPub1 = decodeMultikey(EXPECTED_MULTIKEY1);
check('Multikey 1 decode', hexEncode(decodedPub1) === hexEncode(pub1));

// --- 3. dag-cbor canonical encoding ---
console.log('\n3. dag-cbor Canonical Encoding');
const genesisPayload = vecObject('identity-genesis', 'payload');
const cborBytes = dagCbor.encode(genesisPayload);
check('CBOR bytes match', hexEncode(cborBytes) === EXPECTED_CBOR_HEX);

// --- 4. CID derivation ---
console.log('\n4. CID Derivation');
const cidBytes = makeCidBytes(cborBytes);
check('CID bytes match', hexEncode(cidBytes) === EXPECTED_CID_HEX, `got ${hexEncode(cidBytes)}`);
const cidString = cidToBase32(cidBytes);
check('CID string match', cidString === EXPECTED_GENESIS_CID, `got ${cidString}`);

// --- 5. DID derivation ---
console.log('\n5. DID Derivation');
const didHash = sha256(cidBytes);
check(
  'DID hash',
  hexEncode(didHash) === vec('identity-genesis', 'didHashHex'),
  `got ${hexEncode(didHash)}`,
);
const fullDid = `did:dfos:${encodeId(didHash)}`;
check('Full DID', fullDid === EXPECTED_DID, `got ${fullDid}`);

// --- 6. JWS verification: genesis ---
console.log('\n6. JWS Verification: Genesis (key 1)');
let result = verifyJws(GENESIS_JWS, pub1);
check('Genesis signature valid', true);
check('Genesis header alg', result.header.alg === 'EdDSA');
check('Genesis header typ', result.header.typ === 'did:dfos:identity-op');
check('Genesis header kid', result.header.kid === vec('identity-genesis', 'kid'));
check('Genesis header cid', result.header.cid === EXPECTED_GENESIS_CID);
check('Genesis payload type', result.payload.type === 'create');
check('Genesis payload version', result.payload.version === 1);

// --- 7. JWS verification: rotation (signed by key 1) ---
console.log('\n7. JWS Verification: Rotation (key 1 signs rotation to key 2)');
result = verifyJws(ROTATION_JWS, pub1);
check('Rotation signature valid', true);
check('Rotation kid is DID URL', result.header.kid === vec('identity-rotation', 'kid'));
check('Rotation header cid', result.header.cid === vec('identity-rotation', 'cid'));
check('Rotation payload type', result.payload.type === 'update');
check(
  'Rotation previousOperationCID',
  result.payload.previousOperationCID === EXPECTED_GENESIS_CID,
);

// --- 7b. JWS verification: delete + restore (signed by key 2) ---
console.log('\n7b. JWS Verification: Delete + Restore (key 2)');
result = verifyJws(DELETE_JWS, pub2);
check('Delete payload type', result.payload.type === 'delete');
check('Delete header cid', result.header.cid === vec('identity-delete', 'cid'));
check(
  'Delete parent is rotation',
  result.payload.previousOperationCID === vec('identity-delete', 'previousOperationCID'),
);
check(
  'Delete CID re-derived',
  cidToBase32(makeCidBytes(dagCbor.encode(result.payload))) === result.header.cid,
);
result = verifyJws(RESTORE_JWS, pub2);
check('Restore payload type', result.payload.type === 'restore');
check('Restore header cid', result.header.cid === vec('identity-restore', 'cid'));
check(
  'Restore parent is delete',
  result.payload.previousOperationCID === vec('identity-restore', 'previousOperationCID'),
);
check(
  'Restore CID re-derived',
  cidToBase32(makeCidBytes(dagCbor.encode(result.payload))) === result.header.cid,
);

// --- 7c. Possession proof: the key proof the rotation carries ---
// The rotation OPERATION is signed by key 1; the envelope embedded in it is
// signed by key 2 — the key being introduced — against the key named in the
// envelope's own payload. That circularity is the possession proof. The payload
// is closed: exactly seven members, one order, one serialization.
console.log('\n7c. Key Proof carried by the Rotation (envelope signed by key 2)');
const rotationResult = verifyJws(ROTATION_JWS, pub1);
const keyProofs = rotationResult.payload.keyProofs as string[];
check('Rotation carries exactly one key proof', Array.isArray(keyProofs) && keyProofs.length === 1);

const kpParts = keyProofs[0]!.split('.');
check('Key proof is a compact JWS', kpParts.length === 3);
const kpHeaderText = new TextDecoder().decode(b64urlDecode(kpParts[0]!));
const kpPayloadText = new TextDecoder().decode(b64urlDecode(kpParts[1]!));
const kpHeader = JSON.parse(kpHeaderText);
const kpPayload = JSON.parse(kpPayloadText);

check('Key proof header alg', kpHeader.alg === 'EdDSA', `got ${String(kpHeader.alg)}`);
check('Key proof header typ', kpHeader.typ === 'did:dfos:key-add', `got ${String(kpHeader.typ)}`);
check('Key proof header is exactly {alg, typ}', Object.keys(kpHeader).length === 2);

// The load-bearing check: the presented octets ARE the canonical serialization.
check(
  'Key proof payload octets are canonical',
  kpPayloadText === KEY_PROOF_CANONICAL_PAYLOAD,
  `got ${kpPayloadText}`,
);
check('Key proof payload has exactly 7 members', Object.keys(kpPayload).length === 7);

let kpCursor = -1;
let kpOrdered = true;
for (const member of KEY_PROOF_MEMBERS) {
  const at = kpPayloadText.indexOf(`"${member}":`);
  if (at <= kpCursor) kpOrdered = false;
  kpCursor = at;
}
check('Key proof members are in canonical order', kpOrdered);

check('Key proof binds the reference DID', kpPayload.did === EXPECTED_DID, `got ${kpPayload.did}`);
check(
  'Key proof prevCID is the genesis CID',
  kpPayload.prevCID === EXPECTED_GENESIS_CID,
  `got ${kpPayload.prevCID}`,
);
check('Key proof roleSet', kpPayload.roleSet === KEY_PROOF_ROLE_SET, `got ${kpPayload.roleSet}`);
check(
  'Key proof names key 2',
  kpPayload.publicKeyMultibase === EXPECTED_MULTIKEY2,
  `got ${kpPayload.publicKeyMultibase}`,
);

// The signature verifies against the key the payload itself names — there is no
// resolver seam here.
const kpPub = decodeMultikey(kpPayload.publicKeyMultibase);
check('Key proof key decodes to key 2', hexEncode(kpPub) === hexEncode(pub2));
const kpSig = b64urlDecode(kpParts[2]!);
check('Key proof signature is 64 bytes', kpSig.length === 64, `got ${kpSig.length}`);
check('Key proof signature scalar is canonical', scalarIsCanonical(kpSig.slice(32, 64)));
check(
  'Key proof signature valid under its own named key',
  ed25519.verify(kpSig, new TextEncoder().encode(`${kpParts[0]}.${kpParts[1]}`), kpPub),
);

// --- 8. JWS verification: content create (signed by key 2) ---
console.log('\n8. JWS Verification: Content Create (key 2)');
result = verifyJws(CONTENT_CREATE_JWS, pub2);
check('Content create signature valid', true);
check('Content create typ', result.header.typ === 'did:dfos:content-op');
check('Content create kid', result.header.kid === vec('content-create', 'kid'));
check('Content create header cid', result.header.cid === vec('content-create', 'cid'));
check('Content create payload type', result.payload.type === 'create');

// --- 9. JWT verification (signed by key 2) ---
console.log('\n9. JWT Verification (key 2)');
result = verifyJws(JWT_TOKEN, pub2);
check('JWT signature valid', true);
check('JWT header alg', result.header.alg === 'EdDSA');
check('JWT payload iss', result.payload.iss === vec('jwt', 'iss'));
check('JWT payload sub', result.payload.sub === vec('jwt', 'sub'));
check('JWT payload aud', result.payload.aud === vec('jwt', 'aud'));

// --- 10. Document CID ---
console.log('\n10. Document CID Verification');
const document = vecObject('document', 'value');
const docCbor = dagCbor.encode(document);
const docCidBytes = makeCidBytes(docCbor);
const docCid = cidToBase32(docCidBytes);
check('Document CID', docCid === vec('document', 'cid'), `got ${docCid}`);

// --- 11. Services genesis JWS verification ---
// An identity create whose payload carries a full-state services discovery
// array. The signature verifies under key 1, and re-encoding the decoded
// payload re-derives the operation CID (services entries ride along in the
// payload map) and the derived DID.
console.log('\n11. Services Genesis JWS Verification (key 1)');
result = verifyJws(SERVICES_GENESIS_JWS, pub1);
check('Services genesis signature valid', true);
check('Services genesis header typ', result.header.typ === 'did:dfos:identity-op');
check('Services genesis header kid', result.header.kid === vec('services-genesis', 'kid'));
check('Services genesis header cid', result.header.cid === EXPECTED_SERVICES_CID);
check('Services genesis payload type', result.payload.type === 'create');

// recompute the operation CID over the decoded payload — the services array is
// part of the canonical CBOR, so a correct re-derivation depends on it.
const servicesCborBytes = dagCbor.encode(result.payload);
const servicesCidBytes = makeCidBytes(servicesCborBytes);
const servicesCid = cidToBase32(servicesCidBytes);
check(
  'Services genesis recomputed CID',
  servicesCid === EXPECTED_SERVICES_CID,
  `got ${servicesCid}`,
);

// derive the DID from the operation CID bytes
const servicesDidSuffix = encodeId(sha256(servicesCidBytes));
check(
  'Services genesis derived DID',
  `did:dfos:${servicesDidSuffix}` === EXPECTED_SERVICES_DID,
  `got did:dfos:${servicesDidSuffix}`,
);

// --- 12. DFOS Credential Verification ---
console.log('\n12. DFOS Credential Verification (key 1)');
result = verifyJws(BROAD_WRITE_VC, pub1);
check('Write credential signature valid', true);
check('Write credential header typ', result.header.typ === 'did:dfos:credential');
check('Write credential header kid', result.header.kid === vec('credential-write', 'kid'));
check('Write credential header cid', result.header.cid === vec('credential-write', 'cid'));
check('Write credential payload type', result.payload.type === 'DFOSCredential');
check('Write credential payload iss', result.payload.iss === EXPECTED_DID);
check('Write credential payload aud', result.payload.aud === vec('credential-write', 'aud'));
check(
  'Write credential att resource',
  (result.payload.att as any[])[0].resource === vec('credential-write', 'resource'),
);
check(
  'Write credential att action',
  (result.payload.att as any[])[0].action === vec('credential-write', 'action'),
);

result = verifyJws(READ_VC, pub1);
check('Read credential signature valid', true);
check(
  'Read credential att action',
  (result.payload.att as any[])[0].action === vec('credential-read', 'action'),
);

// --- 13. Number encoding determinism ---
console.log('\n13. Number Encoding Determinism');

// Integer encoding
const intPayload = vecObject('number-integer', 'value');
const intCbor = dagCbor.encode(intPayload);
const expectedIntHex = vec('number-integer', 'cborHex');
check('Integer CBOR hex', hexEncode(intCbor) === expectedIntHex, `got ${hexEncode(intCbor)}`);
const intCidBytes = makeCidBytes(intCbor);
const intCid = cidToBase32(intCidBytes);
const expectedIntCid = vec('number-integer', 'cid');
check('Integer CID', intCid === expectedIntCid, `got ${intCid}`);

// The float serialization a conforming encoder MUST NOT emit, and the CID it
// yields — the shared vector every suite pins as the known-wrong answer.
const nonCanonicalFloatCid = cidToBase32(
  makeCidBytes(hexDecode(vec('number-integer', 'floatCborHex'))),
);
check(
  'Float CBOR yields the known-wrong CID',
  nonCanonicalFloatCid === vec('number-integer', 'floatCid'),
  `got ${nonCanonicalFloatCid}`,
);
check('Float CID differs from the integer CID', nonCanonicalFloatCid !== expectedIntCid);

// JSON parse preserves integers
const jsonPayload = JSON.parse('{"version": 1, "type": "test"}');
const jsonCbor = dagCbor.encode(jsonPayload);
const jsonCidBytes = makeCidBytes(jsonCbor);
const jsonCid = cidToBase32(jsonCidBytes);
check('JSON int parsed as int (not float)', jsonCid === expectedIntCid, `got ${jsonCid}`);

// Float encoding produces wrong CID
const floatPayload = { version: 1.0, type: 'test' };
// Note: in JS, 1.0 === 1 (same number), so dag-cbor will encode as integer.
// This is correct behavior — JS doesn't distinguish int/float for whole numbers.
// The test verifies that dag-cbor doesn't introduce float encoding for whole numbers.
const floatCbor = dagCbor.encode(floatPayload);
const floatCidBytes = makeCidBytes(floatCbor);
const floatCid = cidToBase32(floatCidBytes);
check(
  'Whole-number float encodes as integer (JS semantics)',
  floatCid === expectedIntCid,
  `got ${floatCid}`,
);

// --- 14. Reject corpus (profile + signature gates) ---
// Every conformant verifier MUST reject all of these. Byte-identical inputs
// across all five language suites. Reference key 1 signs the base vector.
console.log('\n14. Reject Corpus (all MUST be rejected)');

const rejectPub = hexDecode(vec('reject-corpus', 'publicKeyHex'));

const REJECT_VECTORS = vecObject('reject-corpus', 'tokens') as Record<string, string>;

for (const [name, token] of Object.entries(REJECT_VECTORS)) {
  let rejected = false;
  try {
    verifyJws(token, rejectPub);
  } catch {
    rejected = true;
  }
  check(`${name} rejected`, rejected, 'was accepted');
}

// --- 15. WP-0 number-policy vectors ---
// dag-cbor number policy: integers must be exact and within ±(2^53-1);
// fractions and non-finite values are non-canonicalizable.
console.log('\n15. WP-0 Number Policy');

const MAX_SAFE = 9007199254740991; // 2^53 - 1

function assertCanonicalNumbers(value: unknown): void {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite');
    if (!Number.isInteger(value)) throw new Error('non-integer');
    if (value > MAX_SAFE || value < -MAX_SAFE) throw new Error('out of safe range');
    return;
  }
  if (Array.isArray(value)) {
    for (const e of value) assertCanonicalNumbers(e);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const e of Object.values(value)) assertCanonicalNumbers(e);
  }
}

function numberCid(value: unknown): string {
  assertCanonicalNumbers(value);
  const cbor = dagCbor.encode(value);
  return cidToBase32(makeCidBytes(cbor));
}

// accept: 2^53-1
check(
  'accept int 2^53-1',
  numberCid(vecObject('number-max-safe', 'value')) === vec('number-max-safe', 'cid'),
  'wrong CID',
);

// reject: 2^53, 1.5, NaN, +Inf, -Inf
for (const [name, bad] of [
  ['2^53', 9007199254740992],
  ['1.5', 1.5],
  ['NaN', NaN],
  ['+Inf', Infinity],
  ['-Inf', -Infinity],
] as [string, number][]) {
  let rejected = false;
  try {
    numberCid({ x: bad });
  } catch {
    rejected = true;
  }
  check(`reject ${name}`, rejected, 'was accepted');
}

// null vector: { documentCID: null, note: null, prf: [] }
check(
  'null vector CID',
  numberCid(vecObject('number-null-vector', 'value')) === vec('number-null-vector', 'cid'),
  'wrong CID',
);

// --- Summary ---
console.log(`\n${'='.repeat(70)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('='.repeat(70));
process.exit(failed > 0 ? 1 : 0);
