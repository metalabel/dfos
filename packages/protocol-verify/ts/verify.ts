/**
 * DFOS Protocol — Independent verification in TypeScript
 *
 * Verifies all deterministic reference artifacts from the protocol specification.
 * Uses only direct crypto dependencies — NOT @metalabel/dfos-protocol.
 *
 * Run: npx tsx verify.ts
 */

import { createHash } from 'node:crypto';
import * as dagCbor from '@ipld/dag-cbor';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { base32 } from 'multiformats/bases/base32';
import { base58btc } from 'multiformats/bases/base58';

// =============================================================================
// Constants from the reference spec
// =============================================================================

const ALPHABET = '2346789acdefhknrtvz';
const ID_LENGTH = 22;

const GENESIS_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw';

const ROTATION_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNpZCI6ImJhZnlyZWljeW00Y3lpZWRubGQ3M3NtYngzMnN6YWVpN3hkdWxxbjRnM3N0ZTVlMncydWxhanIzb3FtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.MScuoBlgOK3j5QX9tFcw1ou0o4LgJziGJEsZ5pvqiBr1SagAyAv5h-wajQhtg8IP7dLlM0U4leW2iRra945cDg';

const CONTENT_CREATE_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwiY2lkIjoiYmFmeXJlaWFlZGhqcTY0YWFqcHdvY2lhaGw1dzM3ajZ1b3hyNW1vam9xNWRuYWg2ZnB2eHI1ZDRseHUifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWh6d3VvdXBmZzNkeGlwNnhtZ3pteHN5d3lpaTJqZW94eHpiZ3gzenhtMmluN2tub2kzZzQiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.Rv6vlz5MfrwqDUrSVIGs4ZfeBbkQUSBcXhxwZ6hfudSr5MxhYl08hTqLDOA0W1NMjN0Hs0IW9jXTwLwP1dMDBg';

const JWT_TOKEN =
  'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIn0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.zhKeXJHHF7a1-MwF4QoUTRptCplAwh20-rLnuWGDFT6uJheN4E_SA5NhqvMNflLHxd7h97gdaVnMZGE67SXEBA';

const BROAD_WRITE_VC =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwiY2lkIjoiYmFmeXJlaWh6dDV3Nmt4YnlsZWZ1N2R3ZDRmbnZxdnlueHphNnhud3N6bXpoYml6anVjNnhjeHFkNmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42IiwiYXVkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6ayIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.brsN3WSdTLhN5-c0mhDriiKa2FuDD3eW5Mlj3KJYcj0cKQH0RDSACMp3qLeN2DGop-kfOtqtxlS7SAMIuCZGAw';

const READ_VC =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwiY2lkIjoiYmFmeXJlaWMzbmJxemFicmxtbnl2a3o3cXI3Znk2cGd4NGFwdm52eWJvNWtzaGN6bXViaXFzemdod2EifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42IiwiYXVkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6ayIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.QB-qK89S-sYXaDUkJJSF5ZbsV2djFFvRQlHCj6UDyl-47LZI-ISwwyqRV-zi6MEGdHb0seSkPxpE4if6HHvvCw';

const BEACON_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYzJtdXg0cGxpNXFmZDVzYnAyeXh5MmdqbTU0Zmc1Z2NpNm02YnBldm9pdXdmZGc2cG91NCJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1hbmlmZXN0Q29udGVudElkIjoiYTgyejkyYTNobmRrNmM5N3RoY3JuOCIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9._EKV036utOU-oMHwMyJ1Om1QhJzN-g9DTRbMz0U7L9SzQR-sHIeC6iNreYN-oV-mBvo5RPLg4TJ0UNv-PNBzDQ';

const BEACON_WITNESS_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X2V6OWE4NzR0Y2tyM2R2OTMzZDNja2QiLCJjaWQiOiJiYWZ5cmVpYzJtdXg0cGxpNXFmZDVzYnAyeXh5MmdqbTU0Zmc1Z2NpNm02YnBldm9pdXdmZGc2cG91NCJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1hbmlmZXN0Q29udGVudElkIjoiYTgyejkyYTNobmRrNmM5N3RoY3JuOCIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.a2BN31Mqi296FJ8wIVOwy7zdTR4fEL2TVy2A6xG6SGUBmJdUdnlqro5JbjIOF-h5RSA1SW0i4WvIK-AeiB27BQ';

const EXPECTED_GENESIS_CID = 'bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy';
const EXPECTED_DID = 'did:dfos:e3vvtck42d4eacdnzvtrn6';
const EXPECTED_MULTIKEY1 = 'z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb';
const EXPECTED_CBOR_HEX =
  'a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62';
const EXPECTED_CID_HEX = '01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486';
const EXPECTED_BEACON_CID = 'bafyreic2mux4pli5qfd5sbp2yxy2gjm54fg5gci6m6bpevoiuwfdg6pou4';

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

function verifyJws(
  token: string,
  pubKeyBytes: Uint8Array,
): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('invalid JWS');
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = b64urlDecode(sigB64);

  const valid = ed25519.verify(signature, signingInput, pubKeyBytes);
  if (!valid) throw new Error('signature verification failed');

  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64)));
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
check(
  'Key 1 private',
  hexEncode(seed1) === '132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac',
);
check(
  'Key 1 public',
  hexEncode(pub1) === 'ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32',
);

const seed2 = sha256(new TextEncoder().encode('dfos-protocol-reference-key-2'));
const pub2 = ed25519.getPublicKey(seed2);
check(
  'Key 2 private',
  hexEncode(seed2) === '384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8',
);
check(
  'Key 2 public',
  hexEncode(pub2) === '0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c',
);

// --- 2. Multikey encoding ---
console.log('\n2. Multikey Encoding');
const multikey1 = encodeMultikey(pub1);
check('Multikey 1 encode', multikey1 === EXPECTED_MULTIKEY1, `got ${multikey1}`);
const decodedPub1 = decodeMultikey(EXPECTED_MULTIKEY1);
check('Multikey 1 decode', hexEncode(decodedPub1) === hexEncode(pub1));

// --- 3. dag-cbor canonical encoding ---
console.log('\n3. dag-cbor Canonical Encoding');
const genesisPayload = {
  version: 1,
  type: 'create',
  authKeys: [
    {
      id: 'key_r9ev34fvc23z999veaaft8',
      type: 'Multikey',
      publicKeyMultibase: EXPECTED_MULTIKEY1,
    },
  ],
  assertKeys: [
    {
      id: 'key_r9ev34fvc23z999veaaft8',
      type: 'Multikey',
      publicKeyMultibase: EXPECTED_MULTIKEY1,
    },
  ],
  controllerKeys: [
    {
      id: 'key_r9ev34fvc23z999veaaft8',
      type: 'Multikey',
      publicKeyMultibase: EXPECTED_MULTIKEY1,
    },
  ],
  createdAt: '2026-03-07T00:00:00.000Z',
};
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
  hexEncode(didHash) === '4360cfbcbbb3f1614c8e02dbfe8d55935e1195cd2129820ab8aef94bde12ea8a',
);
const didSuffix = encodeId(didHash);
check('DID suffix', didSuffix === 'e3vvtck42d4eacdnzvtrn6', `got ${didSuffix}`);
const fullDid = `did:dfos:${didSuffix}`;
check('Full DID', fullDid === EXPECTED_DID);

// --- 6. JWS verification: genesis ---
console.log('\n6. JWS Verification: Genesis (key 1)');
let result = verifyJws(GENESIS_JWS, pub1);
check('Genesis signature valid', true);
check('Genesis header alg', result.header.alg === 'EdDSA');
check('Genesis header typ', result.header.typ === 'did:dfos:identity-op');
check('Genesis header kid', result.header.kid === 'key_r9ev34fvc23z999veaaft8');
check('Genesis header cid', result.header.cid === EXPECTED_GENESIS_CID);
check('Genesis payload type', result.payload.type === 'create');
check('Genesis payload version', result.payload.version === 1);

// --- 7. JWS verification: rotation (signed by key 1) ---
console.log('\n7. JWS Verification: Rotation (key 1 signs rotation to key 2)');
result = verifyJws(ROTATION_JWS, pub1);
check('Rotation signature valid', true);
check(
  'Rotation kid is DID URL',
  result.header.kid === `${EXPECTED_DID}#key_r9ev34fvc23z999veaaft8`,
);
check(
  'Rotation header cid',
  result.header.cid === 'bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm',
);
check('Rotation payload type', result.payload.type === 'update');
check(
  'Rotation previousOperationCID',
  result.payload.previousOperationCID === EXPECTED_GENESIS_CID,
);

// --- 8. JWS verification: content create (signed by key 2) ---
console.log('\n8. JWS Verification: Content Create (key 2)');
result = verifyJws(CONTENT_CREATE_JWS, pub2);
check('Content create signature valid', true);
check('Content create typ', result.header.typ === 'did:dfos:content-op');
check('Content create kid', result.header.kid === `${EXPECTED_DID}#key_ez9a874tckr3dv933d3ckd`);
check(
  'Content create header cid',
  result.header.cid === 'bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu',
);
check('Content create payload type', result.payload.type === 'create');

// --- 9. JWT verification (signed by key 2) ---
console.log('\n9. JWT Verification (key 2)');
result = verifyJws(JWT_TOKEN, pub2);
check('JWT signature valid', true);
check('JWT header alg', result.header.alg === 'EdDSA');
check('JWT payload iss', result.payload.iss === 'dfos');
check('JWT payload sub', result.payload.sub === EXPECTED_DID);
check('JWT payload aud', result.payload.aud === 'dfos-api');

// --- 10. Document CID ---
console.log('\n10. Document CID Verification');
const document = {
  $schema: 'https://schemas.dfos.com/post/v1',
  format: 'short-post',
  title: 'Hello World',
  body: 'First post on the protocol.',
  createdByDID: EXPECTED_DID,
};
const docCbor = dagCbor.encode(document);
const docCidBytes = makeCidBytes(docCbor);
const docCid = cidToBase32(docCidBytes);
check(
  'Document CID',
  docCid === 'bafyreihzwuoupfg3dxip6xmgzmxsywyii2jeoxxzbgx3zxm2in7knoi3g4',
  `got ${docCid}`,
);

// --- 11. Beacon JWS verification ---
console.log('\n11. Beacon JWS Verification (key 1)');
result = verifyJws(BEACON_JWS, pub1);
check('Beacon signature valid', true);
check('Beacon header typ', result.header.typ === 'did:dfos:beacon');
check('Beacon header kid', result.header.kid === `${EXPECTED_DID}#key_r9ev34fvc23z999veaaft8`);
check('Beacon header cid', result.header.cid === EXPECTED_BEACON_CID);
check('Beacon payload type', result.payload.type === 'beacon');
check(
  'Beacon payload manifestContentId',
  result.payload.manifestContentId === 'a82z92a3hndk6c97thcrn8',
);

// --- 12. Beacon countersignature verification ---
console.log("\n12. Beacon Countersignature Verification (key 2 witnesses key 1's beacon)");
result = verifyJws(BEACON_WITNESS_JWS, pub2);
check('Beacon countersig valid', true);
check('Beacon countersig typ', result.header.typ === 'did:dfos:beacon');
check('Beacon countersig kid', result.header.kid === `${EXPECTED_DID}#key_ez9a874tckr3dv933d3ckd`);
check('Beacon countersig same CID', result.header.cid === EXPECTED_BEACON_CID);
check(
  'Beacon countersig same manifestContentId',
  result.payload.manifestContentId === 'a82z92a3hndk6c97thcrn8',
);

// --- 13. DFOS Credential Verification ---
console.log('\n13. DFOS Credential Verification (key 1)');
result = verifyJws(BROAD_WRITE_VC, pub1);
check('Write credential signature valid', true);
check('Write credential header typ', result.header.typ === 'did:dfos:credential');
check(
  'Write credential header kid',
  result.header.kid === `${EXPECTED_DID}#key_r9ev34fvc23z999veaaft8`,
);
check(
  'Write credential header cid',
  typeof result.header.cid === 'string' && (result.header.cid as string).startsWith('bafyrei'),
);
check('Write credential payload type', result.payload.type === 'DFOSCredential');
check('Write credential payload iss', result.payload.iss === EXPECTED_DID);
check('Write credential payload aud', result.payload.aud === 'did:dfos:nzkf838efr424433rn2rzk');
check('Write credential att resource', (result.payload.att as any[])[0].resource === 'chain:*');
check('Write credential att action', (result.payload.att as any[])[0].action === 'write');

result = verifyJws(READ_VC, pub1);
check('Read credential signature valid', true);
check('Read credential att action', (result.payload.att as any[])[0].action === 'read');

// --- 14. Number encoding determinism ---
console.log('\n14. Number Encoding Determinism');

// Integer encoding
const intPayload = { version: 1, type: 'test' };
const intCbor = dagCbor.encode(intPayload);
const expectedIntHex = 'a2647479706564746573746776657273696f6e01';
check('Integer CBOR hex', hexEncode(intCbor) === expectedIntHex, `got ${hexEncode(intCbor)}`);
const intCidBytes = makeCidBytes(intCbor);
const intCid = cidToBase32(intCidBytes);
const expectedIntCid = 'bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa';
check('Integer CID', intCid === expectedIntCid, `got ${intCid}`);

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

// --- Summary ---
console.log(`\n${'='.repeat(70)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('='.repeat(70));
process.exit(failed > 0 ? 1 : 0);
