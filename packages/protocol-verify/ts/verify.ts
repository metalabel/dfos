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
const ID_LENGTH = 31;

const GENESIS_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.TeznHnzrtKOGTr0FzkDL2z-luMWnAbKXrmDbi-Exgw_xMPCnYwGHORMjw-BM28f0RoTirIAeD7d20W5RSuGuBg';

const ROTATION_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWliZnVoNjN1djMzaTJpNWVvb2UzYm9pdDJydXlqZWh1YnNyeWVtdXV6Nm1ydGxlajI2cmVpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.7fqvWGEVYW9atA1uqpp7lIUOWp4dATLpLjOmFWzJN-8gTL-QnXDCeyGcBu5AXhHzO52fauwUavh1KrB6wBYuCw';

const CONTENT_CREATE_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWZ3ZW1ybnR1cG92M3dsZXVib3plMzIyYnAzYnRwYmZzZDJ5d2pwZnJka3VkandyNGpxb2UifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWhxN2I2d2JwZXhlcHhubW0yNXJzY2RzNXB1bm53M2tuZ2RqM3ZtMmg1d3p1b2lxbHRlcmkiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.hwRdbbOdyl4noERFW28YfurNF-5tlpuWBj_gm_9u0iKI17r98s0mO_7DSdD7b4B0rwcfnOHyVYPUCHttmUYdCg';

const JWT_TOKEN =
  'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4In0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.VdrDMOQoFAboxK165ZDOe5YXTgILUDO_bHuGHinupqEd4dptibATmyI9YrjseMaJHS4gggzX1st9qO5eoVJdCQ';

const BROAD_WRITE_VC =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWZ5aW5ieGhicml0NTZtM2FhdjY2bXc0eGQ2YWRxamFzdmNmaG11NjZnNnRudXFncnljbG0ifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.A-EygURAN2bALVwI2AZKFEuy30ZnWJFBaD4jCTf1d7A90rYELStjTWJ1iI7OulihTCfaVtlvj5HtX6Dwv1VxAg';

const READ_VC =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWN0aGNiaXp4dmdlbXN4djdrc2NvbzdhcGllYWFsM2Z5ZTM3bzQ1Zmt5a25lN2I0aG9icmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.UvTItuWFriA39FZIdB5TuXa_b07eyNLc-iR0cej2litSkjBYAZaLlDJUmyDQ-3dB7TmNVXDbB3SMbpvLnWW9Dw';

// Services genesis: an identity create whose payload carries a full-state
// services discovery array (relay locator + content/artifact anchors). The
// services fields ride along in the payload map — no services-validation logic
// is required here; the verifier re-derives the operation CID over the decoded
// payload and the services entries participate automatically.
const SERVICES_GENESIS_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpYnZxZDdmM2hqMzI3ZG9kbXBseDUzeGh2NHdnZXZiNjNmYWl1ZXF0eW9qNmlyb2x1N25qaSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJzZXJ2aWNlcyI6W3siaWQiOiJyZWxheSIsInR5cGUiOiJEZm9zUmVsYXkiLCJlbmRwb2ludCI6Imh0dHBzOi8vcmVsYXkuZGZvcy5jb20ifSx7ImlkIjoicHJvZmlsZSIsInR5cGUiOiJDb250ZW50QW5jaG9yIiwibGFiZWwiOiJwcm9maWxlIiwiYW5jaG9yIjoiOTQzdjhyemRyOWZkcjR6Nzd0ZjhkZThobjNhZmVkNCJ9LHsiaWQiOiJhdmF0YXIiLCJ0eXBlIjoiQ29udGVudEFuY2hvciIsImxhYmVsIjoiYXZhdGFyIiwiYW5jaG9yIjoiYmFmeXJlaWhxN2I2d2JwZXhlcHhubW0yNXJzY2RzNXB1bm53M2tuZ2RqM3ZtMmg1d3p1b2lxbHRlcmkifV0sImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.ORU6Gad1tOiPihC-UN94PlBzccpFz8HbTPLrMmjz87El0MqD4J_61s3BVc-NjY9ARh7gpLZL2hwzwzO-GOl3AQ';

const EXPECTED_GENESIS_CID = 'bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne';
const EXPECTED_SERVICES_CID = 'bafyreibvqd7f3hj327dodmplx53xhv4wgevb63faiueqtyoj6irolu7nji';
const EXPECTED_SERVICES_DID = 'did:dfos:4ve48tvhnvzd9zt9n3tctr93afzczvz';
const EXPECTED_DID = 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr';
const EXPECTED_MULTIKEY1 = 'z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb';
const EXPECTED_CBOR_HEX =
  'a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62';
const EXPECTED_CID_HEX = '017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69';

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
      id: 'key_r9ev34fvc23z999veaaft83nn29zvhe',
      type: 'Multikey',
      publicKeyMultibase: EXPECTED_MULTIKEY1,
    },
  ],
  assertKeys: [
    {
      id: 'key_r9ev34fvc23z999veaaft83nn29zvhe',
      type: 'Multikey',
      publicKeyMultibase: EXPECTED_MULTIKEY1,
    },
  ],
  controllerKeys: [
    {
      id: 'key_r9ev34fvc23z999veaaft83nn29zvhe',
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
  hexEncode(didHash) === 'c66d21f27dceea0b05534c225ad7018ac7d4dfded0609dcd18022a3739a5488c',
);
const didSuffix = encodeId(didHash);
check('DID suffix', didSuffix === 'cnnnft9f8a2rn938d6nkz38r847v2kr', `got ${didSuffix}`);
const fullDid = `did:dfos:${didSuffix}`;
check('Full DID', fullDid === EXPECTED_DID);

// --- 6. JWS verification: genesis ---
console.log('\n6. JWS Verification: Genesis (key 1)');
let result = verifyJws(GENESIS_JWS, pub1);
check('Genesis signature valid', true);
check('Genesis header alg', result.header.alg === 'EdDSA');
check('Genesis header typ', result.header.typ === 'did:dfos:identity-op');
check('Genesis header kid', result.header.kid === 'key_r9ev34fvc23z999veaaft83nn29zvhe');
check('Genesis header cid', result.header.cid === EXPECTED_GENESIS_CID);
check('Genesis payload type', result.payload.type === 'create');
check('Genesis payload version', result.payload.version === 1);

// --- 7. JWS verification: rotation (signed by key 1) ---
console.log('\n7. JWS Verification: Rotation (key 1 signs rotation to key 2)');
result = verifyJws(ROTATION_JWS, pub1);
check('Rotation signature valid', true);
check(
  'Rotation kid is DID URL',
  result.header.kid === `${EXPECTED_DID}#key_r9ev34fvc23z999veaaft83nn29zvhe`,
);
check(
  'Rotation header cid',
  result.header.cid === 'bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei',
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
check(
  'Content create kid',
  result.header.kid === `${EXPECTED_DID}#key_ez9a874tckr3dv933d3ckdn7z6zrct8`,
);
check(
  'Content create header cid',
  result.header.cid === 'bafyreifwemrntupov3wleuboze322bp3btpbfsd2ywjpfrdkudjwr4jqoe',
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
  credits: [{ did: EXPECTED_DID, label: 'author' }],
};
const docCbor = dagCbor.encode(document);
const docCidBytes = makeCidBytes(docCbor);
const docCid = cidToBase32(docCidBytes);
check(
  'Document CID',
  docCid === 'bafyreihq7b6wbpexepxnmm25rscds5punnw3kngdj3vm2h5wzuoiqlteri',
  `got ${docCid}`,
);

// --- 11. Services genesis JWS verification ---
// An identity create whose payload carries a full-state services discovery
// array. The signature verifies under key 1, and re-encoding the decoded
// payload re-derives the operation CID (services entries ride along in the
// payload map) and the derived DID.
console.log('\n11. Services Genesis JWS Verification (key 1)');
result = verifyJws(SERVICES_GENESIS_JWS, pub1);
check('Services genesis signature valid', true);
check('Services genesis header typ', result.header.typ === 'did:dfos:identity-op');
check('Services genesis header kid', result.header.kid === 'key_r9ev34fvc23z999veaaft83nn29zvhe');
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
check(
  'Write credential header kid',
  result.header.kid === `${EXPECTED_DID}#key_r9ev34fvc23z999veaaft83nn29zvhe`,
);
check(
  'Write credential header cid',
  typeof result.header.cid === 'string' && (result.header.cid as string).startsWith('bafyrei'),
);
check('Write credential payload type', result.payload.type === 'DFOSCredential');
check('Write credential payload iss', result.payload.iss === EXPECTED_DID);
check(
  'Write credential payload aud',
  result.payload.aud === 'did:dfos:94ah7963n223k8c9884hh27ekh42nea',
);
check('Write credential att resource', (result.payload.att as any[])[0].resource === 'chain:*');
check('Write credential att action', (result.payload.att as any[])[0].action === 'write');

result = verifyJws(READ_VC, pub1);
check('Read credential signature valid', true);
check('Read credential att action', (result.payload.att as any[])[0].action === 'read');

// --- 13. Number encoding determinism ---
console.log('\n13. Number Encoding Determinism');

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

// --- 14. Reject corpus (profile + signature gates) ---
// Every conformant verifier MUST reject all of these. Byte-identical inputs
// across all five language suites. Reference key 1 signs the base vector.
console.log('\n14. Reject Corpus (all MUST be rejected)');

const REJECT_PUB1_HEX = 'ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32';
const rejectPub = hexDecode(REJECT_PUB1_HEX);

const REJECT_VECTORS: Record<string, string> = {
  'RV-LEN-SHORT':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2',
  'RV-LEN-LONG':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQA',
  'RV-S-NONCANON-PLUSL':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAFq4vaNrS7wPMIBVCWm3qp0JC5obhbU0QOP589IkS2GQ',
  'RV-S-NONCANON-FF':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAD__________________________________________w',
  'RV-ALG-NONE':
    'eyJhbGciOiJub25lIiwidHlwIjoiZGlkOmRmb3M6cmVqZWN0LXZlY3RvciIsImtpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4In0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ',
  'RV-ALG-CASE':
    'eyJhbGciOiJlZGRzYSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ',
  'RV-CRIT-PRESENT':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNyaXQiOlsiZXhwIl19.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ',
  'RV-HEADER-KEY-TRUST':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkFBQUEifX0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ',
  'RV-SIG-BITFLIP':
    'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CA',
};

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
  numberCid({ n: MAX_SAFE }) === 'bafyreieak45zq2337oaadtvk2vwtdqfvfg26hd7olnf275qiv5hrh3vywq',
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
  numberCid({ documentCID: null, note: null, prf: [] }) ===
    'bafyreign22f4jiww2ywlssx7r2l76z32suj5ufvwl354hsp4xrm26cw7ue',
  'wrong CID',
);

// --- Summary ---
console.log(`\n${'='.repeat(70)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('='.repeat(70));
process.exit(failed > 0 ? 1 : 0);
