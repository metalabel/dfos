/*

  KEY-PROOF — byte contract + envelope verification

  The load-bearing piece is `keyProofSigningInput`: the PURE bytes both halves
  share. Every literal in the vector block below is pinned byte-identically in
  packages/dfos-protocol-go/key_proof_test.go — if one side moves, both suites go
  red rather than the two signers silently forking. The cross-language claim the
  vectors make is stronger than "same canonical bytes": the SIGNED envelope is
  pinned too, so a TS-signed proof verifies in Go and a Go-signed proof verifies
  here, because both are the same string.

  Step 6 (nonce bookkeeping) is the CALLER's and is therefore untestable here —
  `verifyKeyProof` performs steps 1–5 and 7. What IS tested is that a verified
  proof hands its nonce back, which is the seam step 6 hangs off.

*/

import { describe, expect, it } from 'vitest';
import { encodeEd25519Multikey } from '../src/chain/multikey';
import {
  base64urlDecode,
  base64urlEncode,
  importEd25519Keypair,
  isValidEd25519Signature,
  signPayloadEd25519,
} from '../src/crypto';
import {
  DEFAULT_KEY_PROOF_SKEW_SECONDS,
  KEY_ADD_JWS_TYP,
  KEY_ROLES,
  keyProofSigningInput,
  KeyProofVerifyError,
  MAX_KEY_PROOF_SIZE,
  parseRoleSet,
  serializeRoleSet,
  signKeyProof,
  verifyChainKeyProof,
  verifyKeyProof,
  type KeyProofPayload,
} from '../src/key-proof';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// -----------------------------------------------------------------------------
// the cross-language vector set — MUST match key_proof_test.go byte for byte
// -----------------------------------------------------------------------------

/** The fixed seed both languages use: bytes 0x20..0x3f. */
const VECTOR_SEED = Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index);
/** A SECOND fixed seed, bytes 0x40..0x5f — the wrong-signer negative. */
const OTHER_SEED = Uint8Array.from({ length: 32 }, (_, index) => 0x40 + index);

const VECTOR_NONCE = 'nonce-key-proof-vector-0001';
const VECTOR_AUDIENCE = 'keys.dfos.com';
const VECTOR_DID = 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae';
/**
 * A PROPER SUBSET on purpose. The full set would make the walk's coverage rule
 * and presentation-time's equality rule indistinguishable, and coverage-not-
 * equality is the one place the two modes deliberately differ.
 */
const VECTOR_ROLE_SET = 'auth,assert';
const VECTOR_PREV_CID = 'bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne';
const VECTOR_TIMESTAMP = '2026-03-07T00:00:00.000Z';
/** Unix seconds of VECTOR_TIMESTAMP — the instant a verifier's clock is pinned to. */
const VECTOR_UNIX = 1772841600;
const VECTOR_MULTIBASE = 'z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2';
const OTHER_MULTIBASE = 'z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG';

const VECTOR_CANONICAL =
  '{"nonce":"nonce-key-proof-vector-0001","audience":"keys.dfos.com","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae","roleSet":"auth,assert","prevCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","publicKeyMultibase":"z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2","timestamp":"2026-03-07T00:00:00.000Z"}';
const VECTOR_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.KepNMLYBmZbnB4l4rNcLOhZS-NOgQHr_a9_So0REHwzoT_jXtVF9XEEeiUNzxxSh965ZfZdNQJteK8Tf6OcuAg';

/** The SAME fixture under a second purpose — the proof that `typ` is a parameter. */
const VECTOR_OTHER_TYP = 'did:dfos:key-proof-vector-other';
const VECTOR_OTHER_TYP_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1wcm9vZi12ZWN0b3Itb3RoZXIifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.KYh81pniAUn0n-ss4Z9_PJCpJkCtryCt8U3ZQhTt3zzjGRzE0v1qyarYjmMUin9eN6bJ1cMXCx6cupyUMDMcDA';

/**
 * THE MALLEABILITY NEGATIVES. Both carry the vector's exact seven members, both
 * are REALLY signed by the vector key over the octets they present, and both are
 * refused: the first serializes the members in reverse order, the second inserts
 * insignificant whitespace. A signature covers whatever octets arrived, so the
 * only thing that makes one set of members one payload string is the verifier
 * recomputing the canonical signing input and byte-comparing. Pinned in
 * key_proof_test.go too —
 * a twin that accepted either would be accepting bytes production refuses.
 */
const VECTOR_REORDERED_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJkaWQiOiJkaWQ6ZGZvczpuemtmODM4ZWZyNDI0NDMzcm4ycnprZHY4aDd0OWFlIiwiYXVkaWVuY2UiOiJrZXlzLmRmb3MuY29tIiwibm9uY2UiOiJub25jZS1rZXktcHJvb2YtdmVjdG9yLTAwMDEifQ.4qHdOCS5yAq10_XpdfBFoglwm2ZDLNooUntOyWDjcNul9M2_GbShh8JIOd5vimen0ZKUpObmFFVPlzVcmT0XDw';
const VECTOR_SPACED_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6ICJub25jZS1rZXktcHJvb2YtdmVjdG9yLTAwMDEiLCAiYXVkaWVuY2UiOiAia2V5cy5kZm9zLmNvbSIsICJkaWQiOiAiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6a2R2OGg3dDlhZSIsICJyb2xlU2V0IjogImF1dGgsYXNzZXJ0IiwgInByZXZDSUQiOiAiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCAicHVibGljS2V5TXVsdGliYXNlIjogIno2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsICJ0aW1lc3RhbXAiOiAiMjAyNi0wMy0wN1QwMDowMDowMC4wMDBaIn0.XVCcwA2t1jpxbbotBVsOa96dQecpm0ZpymM53MrCA_r88suegEmMLxva6nVSelNipVmeBuWS7lcTFSb2dNeeDw';

/** The same members signed by the OTHER key, naming the OTHER key. */
const VECTOR_OTHER_KEY_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rZ3hqMlIzSEx0UVJwUG52ZnZwdUtFY2VTcWYzdFpIQmpkbVozZkZ6M0pIR0ciLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.Y2Wd-a7PPXpt6-hLJBRg2V9vLZwMfXa_qxv7ZxtB48OB6l9EotoKYkJhwdOLjv2Ydy-MEnkOkt4_CWEhAgJKCg';

/**
 * The same fixture consenting to ALL THREE roles. Presentation-time refuses it
 * where `auth,assert` was asked (equality); the chain walk accepts it for any one
 * of the three (coverage). One envelope, two different right answers.
 */
const VECTOR_FULL_ROLE_SET_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQsY29udHJvbGxlciIsInByZXZDSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.mK04MC77zaK0oUUS68dsWbdw8IV0ES9wS9xXoxG48sk1uxvE3Tabu6kQFWsvzhgdLxvxX6VPYBiuDJHbz8M2Cg';

const vectorPayload = (): KeyProofPayload => ({
  nonce: VECTOR_NONCE,
  audience: VECTOR_AUDIENCE,
  did: VECTOR_DID,
  roleSet: VECTOR_ROLE_SET,
  prevCID: VECTOR_PREV_CID,
  publicKeyMultibase: VECTOR_MULTIBASE,
  timestamp: VECTOR_TIMESTAMP,
});

/** The producer-side inputs the vector envelope is signed from. */
const vectorSignInput = () => ({
  typ: KEY_ADD_JWS_TYP,
  nonce: VECTOR_NONCE,
  audience: VECTOR_AUDIENCE,
  did: VECTOR_DID,
  roleSet: VECTOR_ROLE_SET,
  prevCID: VECTOR_PREV_CID,
  privateKey: VECTOR_SEED,
  timestamp: VECTOR_TIMESTAMP,
});

const at = (unixSeconds: number) => () => unixSeconds * 1000;

const expectAt = (overrides: Partial<Parameters<typeof verifyKeyProof>[1]> = {}) => ({
  expectedTyp: KEY_ADD_JWS_TYP,
  expectedAudience: VECTOR_AUDIENCE,
  expectedDid: VECTOR_DID,
  expectedRoleSet: VECTOR_ROLE_SET,
  expectedPrevCID: VECTOR_PREV_CID,
  now: at(VECTOR_UNIX),
  ...overrides,
});

const walkFor = (overrides: Partial<Parameters<typeof verifyChainKeyProof>[1]> = {}) => ({
  expectedTyp: KEY_ADD_JWS_TYP,
  did: VECTOR_DID,
  prevCID: VECTOR_PREV_CID,
  publicKeyMultibase: VECTOR_MULTIBASE,
  role: 'auth' as const,
  ...overrides,
});

/**
 * Hand-assemble a signed envelope from arbitrary header and payload objects, so
 * the negative cases can produce artifacts `signKeyProof` would never emit. The
 * signature is always REAL — every rejection below is therefore a rejection by
 * the gate under test, not an accidental signature failure.
 */
const forge = (
  header: Record<string, unknown>,
  payload: unknown,
  seed: Uint8Array = VECTOR_SEED,
): string => {
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  return `${signingInput}.${base64urlEncode(signPayloadEd25519(encoder.encode(signingInput), seed))}`;
};

const reasonOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (err) {
    if (err instanceof KeyProofVerifyError) return err.reason;
    return `not-a-KeyProofVerifyError: ${String(err)}`;
  }
  return 'did-not-throw';
};

// -----------------------------------------------------------------------------

describe('key-proof byte contract', () => {
  it('pins the shared canonical signing input', () => {
    expect(decoder.decode(keyProofSigningInput(vectorPayload()))).toBe(VECTOR_CANONICAL);
  });

  it('is order-independent across object construction', () => {
    const a = vectorPayload();
    const b: KeyProofPayload = {
      timestamp: a.timestamp,
      publicKeyMultibase: a.publicKeyMultibase,
      prevCID: a.prevCID,
      roleSet: a.roleSet,
      did: a.did,
      audience: a.audience,
      nonce: a.nonce,
    };
    expect(keyProofSigningInput(b)).toEqual(keyProofSigningInput(a));
  });

  it('derives publicKeyMultibase from the private key and pins the signed vector', async () => {
    const { proof, payload } = await signKeyProof(vectorSignInput());
    expect(payload.publicKeyMultibase).toBe(VECTOR_MULTIBASE);
    expect(payload.publicKeyMultibase).toBe(
      encodeEd25519Multikey(importEd25519Keypair(VECTOR_SEED).publicKey),
    );
    expect(proof).toBe(VECTOR_JWS);

    // The emitted payload segment IS the signing input. That equivalence is the
    // whole reason there is one byte contract and not two — pin it, do not assume it.
    expect(proof.split('.')[1]).toBe(base64urlEncode(keyProofSigningInput(payload)));
  });

  it('emits a protected header of exactly {alg, typ} — no kid, no cid', () => {
    const header = JSON.parse(decoder.decode(base64urlDecode(VECTOR_JWS.split('.')[0] as string)));
    expect(header).toEqual({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP });
    expect(Object.keys(header)).toEqual(['alg', 'typ']);
  });

  it('serves every registered purpose from the same grammar — typ is a parameter', async () => {
    const { proof } = await signKeyProof({ ...vectorSignInput(), typ: VECTOR_OTHER_TYP });
    expect(proof).toBe(VECTOR_OTHER_TYP_JWS);
    // Same payload segment as the key-add vector: only the header differs.
    expect(proof.split('.')[1]).toBe(VECTOR_JWS.split('.')[1]);
  });

  it('floor-normalizes a millisecond-bearing timestamp, and defaults to now', async () => {
    const floored = await signKeyProof({
      ...vectorSignInput(),
      timestamp: '2026-03-07T00:00:00.987Z',
    });
    expect(floored.payload.timestamp).toBe(VECTOR_TIMESTAMP);
    expect(floored.proof).toBe(VECTOR_JWS);

    const { timestamp: _omitted, ...withoutTimestamp } = vectorSignInput();
    const defaulted = await signKeyProof({
      ...withoutTimestamp,
      now: () => VECTOR_UNIX * 1000 + 654,
    });
    expect(defaulted.payload.timestamp).toBe(VECTOR_TIMESTAMP);
    expect(defaulted.proof).toBe(VECTOR_JWS);
  });

  it('refuses a timestamp override outside the protocol grammar the Go twin parses', async () => {
    for (const timestamp of [
      '2026-03-07T00:00:00Z', // no fraction
      '2026-03-07T00:00:00.12Z', // two digits
      '2026-03-07T00:00:00.000+00:00', // numeric offset
      '2026-03-07T00:00:00.000', // no zone — some runtimes read this as LOCAL
      '2026-02-30T00:00:00.000Z', // not a calendar date
      'yesterday',
    ]) {
      await expect(signKeyProof({ ...vectorSignInput(), timestamp })).rejects.toThrow(
        /unparseable timestamp/,
      );
    }
  });

  it('refuses a payload the closed schema does not admit, on the PRODUCER side too', () => {
    expect(() =>
      keyProofSigningInput({ ...vectorPayload(), extra: 'x' } as KeyProofPayload),
    ).toThrow(/the payload is closed/);
    expect(() => keyProofSigningInput({ ...vectorPayload(), audience: 'KEYS.DFOS.COM' })).toThrow(
      /lowercase authority/,
    );
    expect(() =>
      keyProofSigningInput({ ...vectorPayload(), audience: 'https://keys.dfos.com' }),
    ).toThrow(/lowercase authority/);
    expect(() =>
      keyProofSigningInput({ ...vectorPayload(), audience: 'keys.dfos.com/complete' }),
    ).toThrow(/lowercase authority/);
    expect(() =>
      keyProofSigningInput({ ...vectorPayload(), timestamp: '2026-03-07T00:00:00Z' }),
    ).toThrow(/whole-second/);
    for (const member of ['did', 'roleSet', 'prevCID'] as const) {
      expect(() => keyProofSigningInput({ ...vectorPayload(), [member]: '' })).toThrow(
        /non-empty string/,
      );
    }
  });
});

// -----------------------------------------------------------------------------
// the role set
// -----------------------------------------------------------------------------

describe('role set — one spelling per set', () => {
  it('serializes any input order to the fixed auth,assert,controller order', () => {
    expect(serializeRoleSet(['controller', 'auth'])).toBe('auth,controller');
    expect(serializeRoleSet(['assert', 'auth'])).toBe('auth,assert');
    expect(serializeRoleSet(['controller', 'assert', 'auth'])).toBe('auth,assert,controller');
    // A set is a set: duplicates in the input collapse rather than reject.
    expect(serializeRoleSet(['auth', 'auth'])).toBe('auth');
    expect(serializeRoleSet(KEY_ROLES)).toBe('auth,assert,controller');
  });

  it('refuses an unknown role and an empty set on the producer side', () => {
    expect(() => serializeRoleSet(['owner' as never])).toThrow(/unknown role/);
    expect(() => serializeRoleSet([])).toThrow(/at least one role/);
  });

  it('parses exactly the seven canonical spellings and nothing else', () => {
    const canonical = [
      'auth',
      'assert',
      'controller',
      'auth,assert',
      'auth,controller',
      'assert,controller',
      'auth,assert,controller',
    ];
    for (const value of canonical) {
      expect(parseRoleSet(value), value).not.toBeNull();
      expect(serializeRoleSet(parseRoleSet(value) as never), value).toBe(value);
    }
    for (const value of [
      '', // empty
      'assert,auth', // out of order
      'controller,auth', // out of order
      'auth, assert', // whitespace
      ' auth', // whitespace
      'auth,', // empty segment
      ',auth', // empty segment
      'auth,auth', // duplicate
      'auth,owner', // unknown role
      'owner', // unknown role
      'AUTH', // case
      'auth;assert', // wrong separator
    ]) {
      expect(parseRoleSet(value), JSON.stringify(value)).toBeNull();
    }
  });

  it('refuses a non-canonical roleSet inside the envelope — same class as member order', () => {
    for (const roleSet of ['assert,auth', 'auth, assert', 'auth,auth', 'auth,owner', '']) {
      const forged = forge(
        { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP },
        {
          ...vectorPayload(),
          roleSet,
        },
      );
      expect(
        reasonOf(() => verifyKeyProof(forged, expectAt())),
        roleSet,
      ).toBe('schema');
    }
    // ...and the producer half refuses the same spellings before there are bytes.
    expect(() => keyProofSigningInput({ ...vectorPayload(), roleSet: 'assert,auth' })).toThrow(
      /canonical/,
    );
  });
});

describe('key-proof verification — steps 1–5 and 7', () => {
  it('verifies the pinned vector and hands back the nonce for the caller step 6', () => {
    const verified = verifyKeyProof(VECTOR_JWS, expectAt());
    expect(verified.payload).toEqual(vectorPayload());
    expect(verified.typ).toBe(KEY_ADD_JWS_TYP);
    expect(verified.now).toBe(VECTOR_UNIX);
    // Step 6 is the caller's: this is the value it check-and-deletes against.
    expect(verified.payload.nonce).toBe(VECTOR_NONCE);
  });

  it('verifies a proof under any registered purpose the ceremony asks for', () => {
    expect(
      verifyKeyProof(VECTOR_OTHER_TYP_JWS, expectAt({ expectedTyp: VECTOR_OTHER_TYP })).typ,
    ).toBe(VECTOR_OTHER_TYP);
  });

  // --- 1. size cap ---------------------------------------------------------

  it('rejects an oversize envelope BEFORE any decode', () => {
    const oversize = `${'a'.repeat(MAX_KEY_PROOF_SIZE + 1)}`;
    expect(reasonOf(() => verifyKeyProof(oversize, expectAt()))).toBe('size');
    // The cap binds the SIGNER too.
    const huge = { ...vectorPayload(), nonce: 'n'.repeat(MAX_KEY_PROOF_SIZE) };
    expect(() =>
      verifyKeyProof(forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, huge), expectAt()),
    ).toThrow(/exceeds max size/);
  });

  it('refuses to SIGN an envelope over the cap', async () => {
    await expect(
      signKeyProof({ ...vectorSignInput(), nonce: 'n'.repeat(MAX_KEY_PROOF_SIZE) }),
    ).rejects.toThrow(/exceeds max size/);
  });

  // --- 2. header gates -----------------------------------------------------

  it('rejects a PRESENT kid — the candidate key is in no chain', () => {
    const withKid = forge(
      { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP, kid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#key_0' },
      vectorPayload(),
    );
    expect(reasonOf(() => verifyKeyProof(withKid, expectAt()))).toBe('header');
    expect(() => verifyKeyProof(withKid, expectAt())).toThrow(/kid must be absent/);
  });

  it('rejects a crit member', () => {
    const withCrit = forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP, crit: ['b64'] }, vectorPayload());
    expect(reasonOf(() => verifyKeyProof(withCrit, expectAt()))).toBe('header');
    expect(() => verifyKeyProof(withCrit, expectAt())).toThrow(/crit/);
  });

  it('rejects every embedded-key member and every key REFERENCE member', () => {
    for (const member of ['jwk', 'jku', 'x5c', 'x5u']) {
      const forged = forge(
        { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP, [member]: 'https://evil.example/key' },
        vectorPayload(),
      );
      expect(reasonOf(() => verifyKeyProof(forged, expectAt()))).toBe('header');
      expect(() => verifyKeyProof(forged, expectAt())).toThrow(new RegExp(member));
    }
  });

  it('rejects a wrong typ, in both directions', () => {
    // A key-add proof presented where another purpose is required.
    expect(
      reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedTyp: VECTOR_OTHER_TYP }))),
    ).toBe('header');
    // And the reverse.
    expect(reasonOf(() => verifyKeyProof(VECTOR_OTHER_TYP_JWS, expectAt()))).toBe('header');
    // A typ from another family is not a key proof at all.
    const siwdShaped = forge({ alg: 'EdDSA', typ: 'did:dfos:siwd-ask' }, vectorPayload());
    expect(reasonOf(() => verifyKeyProof(siwdShaped, expectAt()))).toBe('header');
  });

  it('rejects a non-EdDSA alg and a malformed envelope', () => {
    expect(
      reasonOf(() =>
        verifyKeyProof(forge({ alg: 'none', typ: KEY_ADD_JWS_TYP }, vectorPayload()), expectAt()),
      ),
    ).toBe('header');
    expect(reasonOf(() => verifyKeyProof('not.a.jws.at.all', expectAt()))).toBe('header');
    expect(reasonOf(() => verifyKeyProof('onlyonepart', expectAt()))).toBe('header');
  });

  // --- 3. closed payload schema -------------------------------------------

  it('rejects an EXTRA member — the payload is closed', () => {
    const extra = forge(
      { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP },
      {
        ...vectorPayload(),
        intent: 'send all my money',
      },
    );
    expect(reasonOf(() => verifyKeyProof(extra, expectAt()))).toBe('schema');
    expect(() => verifyKeyProof(extra, expectAt())).toThrow(/the payload is closed/);
  });

  it('rejects a REORDERED or RE-SPACED payload — the canonical bytes bind the verifier', () => {
    // Every other gate passes: real signature by the named key, right typ, right
    // audience, fresh timestamp, exactly the seven members. What fails is that the
    // presented octets are not the canonical serialization of those members. Left
    // unchecked, one set of members would have unboundedly many payload spellings
    // — and this package would verify payloads the platform's verifier refuses.
    for (const malleable of [VECTOR_REORDERED_JWS, VECTOR_SPACED_JWS]) {
      expect(reasonOf(() => verifyKeyProof(malleable, expectAt()))).toBe('schema');
      expect(() => verifyKeyProof(malleable, expectAt())).toThrow(/canonical signing input/);
      // The members really are the vector's, and the signature really covers the
      // bytes presented — so the refusal is the canonical-bytes gate and nothing else.
      const [header, segment, signature] = malleable.split('.') as [string, string, string];
      expect(JSON.parse(decoder.decode(base64urlDecode(segment)))).toEqual(vectorPayload());
      expect(segment).not.toBe(base64urlEncode(keyProofSigningInput(vectorPayload())));
      expect(
        isValidEd25519Signature(
          encoder.encode(`${header}.${segment}`),
          base64urlDecode(signature),
          importEd25519Keypair(VECTOR_SEED).publicKey,
        ),
      ).toBe(true);
    }
    // ...and the canonical spelling of the same members verifies, so the gate is a
    // byte comparison and not a blanket refusal.
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt())).not.toThrow();
  });

  it('rejects a MISSING member', () => {
    for (const member of [
      'nonce',
      'audience',
      'did',
      'roleSet',
      'prevCID',
      'publicKeyMultibase',
      'timestamp',
    ] as const) {
      const partial: Record<string, unknown> = { ...vectorPayload() };
      delete partial[member];
      expect(
        reasonOf(() =>
          verifyKeyProof(forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, partial), expectAt()),
        ),
      ).toBe('schema');
    }
  });

  it('rejects a NON-STRING member', () => {
    for (const value of [42, null, true, [], { a: 1 }]) {
      const bad = { ...vectorPayload(), nonce: value };
      expect(
        reasonOf(() =>
          verifyKeyProof(forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, bad), expectAt()),
        ),
      ).toBe('schema');
    }
    // A numeric timestamp is the case a lenient parser would coerce.
    const numericTimestamp = { ...vectorPayload(), timestamp: VECTOR_UNIX };
    expect(
      reasonOf(() =>
        verifyKeyProof(forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, numericTimestamp), expectAt()),
      ),
    ).toBe('schema');
  });

  it('rejects a timestamp that is SPELLED right but is not a calendar date', () => {
    // The twin contract's sharpest edge: `Date.parse('2026-02-30T00:00:00.000Z')`
    // NORMALIZES to March 2 and returns a finite number, where the Go twin's
    // `time.Parse` refuses the date outright. A finiteness-only check therefore
    // VERIFIED a correctly-signed proof in TypeScript that Go rejects — two
    // byte-twins disagreeing about whether a proof verifies. The same four
    // fixtures are pinned in key_proof_test.go's Go verify-side mirror.
    for (const [timestamp, unix] of [
      ['2026-02-30T00:00:00.000Z', 1_772_409_600], // February has no 30th
      ['2027-02-29T00:00:00.000Z', 1_803_859_200], // 2027 is not a leap year
    ] as const) {
      const impossible = forge(
        { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP },
        {
          ...vectorPayload(),
          timestamp,
        },
      );
      expect(reasonOf(() => verifyKeyProof(impossible, expectAt({ now: at(unix) })))).toBe(
        'schema',
      );
    }

    // ...and the neighbouring REAL dates still verify, so the gate is a calendar
    // check and not a blanket refusal of February.
    for (const [timestamp, unix] of [
      ['2026-02-28T00:00:00.000Z', 1_772_236_800],
      ['2028-02-29T00:00:00.000Z', 1_835_395_200], // 2028 IS a leap year
    ] as const) {
      const real = forge(
        { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP },
        {
          ...vectorPayload(),
          timestamp,
        },
      );
      expect(() => verifyKeyProof(real, expectAt({ now: at(unix) }))).not.toThrow();
    }
  });

  it('rejects a payload that is not a JSON object', () => {
    for (const payload of [[1, 2, 3], 'a string', 7, null]) {
      expect(
        reasonOf(() =>
          verifyKeyProof(forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, payload), expectAt()),
        ),
      ).toBe('schema');
    }
  });

  // --- 4. audience ---------------------------------------------------------

  it('rejects an audience that does not BYTE-EQUAL the verifier own authority', () => {
    expect(
      reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedAudience: 'evil.example' }))),
    ).toBe('audience');
    // Near-misses are misses: no port normalization, no case folding, no suffix match.
    for (const authority of ['keys.dfos.com:443', 'KEYS.DFOS.COM', 'dfos.com', 'a.keys.dfos.com']) {
      expect(
        reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedAudience: authority }))),
      ).toBe('audience');
    }
  });

  // --- 4b. the three positional arms ---------------------------------------

  it('rejects a did, roleSet or prevCID that is not the one this ceremony is writing', () => {
    // Each arm alone. Every other gate passes, so the reason names the arm — a
    // proof collected for one chain, one role set, or one head is not spendable
    // at another, and each refusal is separately observable.
    expect(
      reasonOf(() =>
        verifyKeyProof(
          VECTOR_JWS,
          expectAt({ expectedDid: 'did:dfos:someotherchain00000000000000' }),
        ),
      ),
    ).toBe('did');
    expect(reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedRoleSet: 'auth' })))).toBe(
      'roleSet',
    );
    expect(
      reasonOf(() =>
        verifyKeyProof(
          VECTOR_JWS,
          expectAt({
            expectedPrevCID: 'bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei',
          }),
        ),
      ),
    ).toBe('prevCID');
  });

  it('takes the roleSet by EQUALITY, so a wider consent is not bankable', () => {
    // The holder consented to all three roles; the ceremony is writing two. That
    // is the holder conceding more than was asked, and a completing authority has
    // no business banking the difference — presentation-time refuses it.
    expect(reasonOf(() => verifyKeyProof(VECTOR_FULL_ROLE_SET_JWS, expectAt()))).toBe('roleSet');
    // Under the matching expectation the very same envelope verifies.
    expect(() =>
      verifyKeyProof(
        VECTOR_FULL_ROLE_SET_JWS,
        expectAt({ expectedRoleSet: 'auth,assert,controller' }),
      ),
    ).not.toThrow();
    // ...and the chain walk reads it the OTHER way: coverage, one role at a time.
    for (const role of KEY_ROLES) {
      expect(() => verifyChainKeyProof(VECTOR_FULL_ROLE_SET_JWS, walkFor({ role }))).not.toThrow();
    }
  });

  it('refuses an EMPTY or non-canonical positional expectation as a MISCONFIGURATION', () => {
    // An arm compared against an empty string binds nothing while reading as
    // present, which is exactly the standing consent the members exist to close.
    // A plain Error, never a KeyProofVerifyError — a broken deployment must not
    // be mistakable for a bad envelope.
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedAudience: '' }))).toThrow(
      /expectedAudience/,
    );
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedDid: '' }))).toThrow(/expectedDid/);
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedPrevCID: '' }))).toThrow(
      /expectedPrevCID/,
    );
    for (const roleSet of ['', 'assert,auth', 'auth, assert', 'owner']) {
      expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedRoleSet: roleSet }))).toThrow(
        /expectedRoleSet/,
      );
    }
    expect(reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ expectedDid: '' })))).toMatch(
      /^not-a-KeyProofVerifyError/,
    );
  });

  // --- 5. freshness --------------------------------------------------------

  it('accepts inside the window on BOTH sides and rejects outside it', () => {
    const edge = DEFAULT_KEY_PROOF_SKEW_SECONDS;
    expect(() =>
      verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX + edge) })),
    ).not.toThrow();
    expect(() =>
      verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX - edge) })),
    ).not.toThrow();
    expect(
      reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX + edge + 1) }))),
    ).toBe('freshness');
    expect(
      reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX - edge - 1) }))),
    ).toBe('freshness');
  });

  it('rejects a plainly stale envelope, and honors a tighter configured window', () => {
    expect(
      reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX + 86_400) }))),
    ).toBe('freshness');
    expect(
      reasonOf(() =>
        verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX + 31), maxSkewSeconds: 30 })),
      ),
    ).toBe('freshness');
    // An explicit 0 is honored, not read as omission.
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ maxSkewSeconds: 0 }))).not.toThrow();
    expect(
      reasonOf(() =>
        verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX + 1), maxSkewSeconds: 0 })),
      ),
    ).toBe('freshness');
  });

  it('refuses a negative or non-integer window as a MISCONFIGURATION, not a verdict', () => {
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ maxSkewSeconds: -1 }))).toThrow(
      /non-negative integer/,
    );
    expect(() => verifyKeyProof(VECTOR_JWS, expectAt({ maxSkewSeconds: 1.5 }))).toThrow(
      /non-negative integer/,
    );
  });

  it('refuses an EMPTY expectedTyp — the gate must name a purpose', async () => {
    // An empty expectation byte-equals an artifact carrying `"typ":""`, so a
    // verifier configured with one admits an envelope scoped to no ceremony at
    // all. Both halves refuse: `signKeyProof` on the producer side, and this on
    // the verifier side. A MISCONFIGURATION, never a verdict — a plain Error, not
    // a KeyProofVerifyError, so a caller branching on `reason` cannot read a
    // broken deployment as a bad envelope. The Go twin pins the same pair.
    await expect(signKeyProof({ ...vectorSignInput(), typ: '' })).rejects.toThrow(
      /registered purpose value/,
    );

    // A REAL signature over a header whose typ is the empty string — the artifact
    // an empty expectation would otherwise wave through.
    const emptyTyp = forge({ alg: 'EdDSA', typ: '' }, vectorPayload());
    expect(() => verifyKeyProof(emptyTyp, expectAt({ expectedTyp: '' }))).toThrow(
      /registered purpose value/,
    );
    expect(reasonOf(() => verifyKeyProof(emptyTyp, expectAt({ expectedTyp: '' })))).toMatch(
      /^not-a-KeyProofVerifyError/,
    );
  });

  // --- 7. signature --------------------------------------------------------

  it('rejects a proof signed by a DIFFERENT key than the one it names', () => {
    // Real signature, real key — but the payload names the vector key and the
    // signature is the other key's. This is the substitution the self-proving
    // circularity exists to catch.
    const mismatched = forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, vectorPayload(), OTHER_SEED);
    expect(reasonOf(() => verifyKeyProof(mismatched, expectAt()))).toBe('signature');

    // The converse is a VALID proof — it names the key that signed it. Naming a
    // different key is what fails, not signing with a different key.
    const honest = verifyKeyProof(VECTOR_OTHER_KEY_JWS, expectAt());
    expect(honest.payload.publicKeyMultibase).toBe(OTHER_MULTIBASE);
  });

  it('rejects a tampered payload segment', () => {
    const tampered = forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, vectorPayload()).split('.');
    const swapped = `${tampered[0]}.${base64urlEncode(
      keyProofSigningInput({ ...vectorPayload(), nonce: 'nonce-key-proof-vector-0002' }),
    )}.${tampered[2]}`;
    expect(reasonOf(() => verifyKeyProof(swapped, expectAt()))).toBe('signature');
  });

  it('rejects an undecodable or non-Ed25519 publicKeyMultibase', () => {
    for (const multibase of ['zNotAMultikey', 'z6Mk', 'not-multibase']) {
      const bad = forge(
        { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP },
        {
          ...vectorPayload(),
          publicKeyMultibase: multibase,
        },
      );
      expect(reasonOf(() => verifyKeyProof(bad, expectAt()))).toBe('signature');
    }
  });

  it('rejects a mangled signature segment without letting the crypto layer throw', () => {
    const parts = VECTOR_JWS.split('.');
    expect(reasonOf(() => verifyKeyProof(`${parts[0]}.${parts[1]}.AAAA`, expectAt()))).toBe(
      'signature',
    );
    expect(reasonOf(() => verifyKeyProof(`${parts[0]}.${parts[1]}.`, expectAt()))).toBe(
      'signature',
    );
  });
});

// -----------------------------------------------------------------------------
// chain-walk verification — the same envelope, read from a different position
// -----------------------------------------------------------------------------

describe('key-proof verification — chain walk', () => {
  it('verifies the pinned vector against a position rather than a ceremony', () => {
    const payload = verifyChainKeyProof(VECTOR_JWS, walkFor());
    expect(payload).toEqual(vectorPayload());
    // The two transport members ride along, verbatim and unchecked.
    expect(payload.nonce).toBe(VECTOR_NONCE);
    expect(payload.audience).toBe(VECTOR_AUDIENCE);
  });

  it('checks NEITHER freshness NOR audience — a chain does not expire, and is not one relay for', () => {
    // A DECADE past the timestamp. Presentation-time refuses this on freshness;
    // the walk does not, because a chain that expired would be a chain no one
    // could replay. There is no clock parameter here at all — the absence is the
    // contract.
    expect(() => verifyChainKeyProof(VECTOR_JWS, walkFor())).not.toThrow();
    expect(
      reasonOf(() => verifyKeyProof(VECTOR_JWS, expectAt({ now: at(VECTOR_UNIX + 315_360_000) }))),
    ).toBe('freshness');
    // ...and no audience parameter either: the envelope is audienced to
    // keys.dfos.com, and a walker on any other host still reads it.
    expect(Object.keys(walkFor())).not.toContain('expectedAudience');
  });

  it('refuses an envelope for a DIFFERENT key, chain, head, or role', () => {
    // The key arm: an honest, fully valid envelope — for the other key.
    expect(reasonOf(() => verifyChainKeyProof(VECTOR_OTHER_KEY_JWS, walkFor()))).toBe('key');
    expect(
      reasonOf(() =>
        verifyChainKeyProof(VECTOR_JWS, walkFor({ did: 'did:dfos:someotherchain00000000000000' })),
      ),
    ).toBe('did');
    // THE STANDING-CONSENT ARM. Same key, same chain, same roles — a head that
    // has moved on. This is what makes a re-add or a promotion need a FRESH
    // envelope: an old one is bound to a head that is no longer the parent.
    expect(
      reasonOf(() =>
        verifyChainKeyProof(
          VECTOR_JWS,
          walkFor({ prevCID: 'bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei' }),
        ),
      ),
    ).toBe('prevCID');
    // Coverage: the vector consents to auth and assert, so controller is uncovered.
    expect(reasonOf(() => verifyChainKeyProof(VECTOR_JWS, walkFor({ role: 'controller' })))).toBe(
      'roleSet',
    );
    for (const role of ['auth', 'assert'] as const) {
      expect(() => verifyChainKeyProof(VECTOR_JWS, walkFor({ role }))).not.toThrow();
    }
  });

  it('applies the SAME artifact gates as presentation time', () => {
    // Size, header, closed schema and canonical bytes are properties of the
    // artifact, not of the reader's position, so both modes refuse identically.
    expect(reasonOf(() => verifyChainKeyProof('a'.repeat(MAX_KEY_PROOF_SIZE + 1), walkFor()))).toBe(
      'size',
    );
    expect(reasonOf(() => verifyChainKeyProof(VECTOR_OTHER_TYP_JWS, walkFor()))).toBe('header');
    for (const malleable of [VECTOR_REORDERED_JWS, VECTOR_SPACED_JWS]) {
      expect(reasonOf(() => verifyChainKeyProof(malleable, walkFor()))).toBe('schema');
    }
    const withKid = forge(
      { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP, kid: `${VECTOR_DID}#key_0` },
      vectorPayload(),
    );
    expect(reasonOf(() => verifyChainKeyProof(withKid, walkFor()))).toBe('header');
    const extra = forge(
      { alg: 'EdDSA', typ: KEY_ADD_JWS_TYP },
      {
        ...vectorPayload(),
        intent: 'send all my money',
      },
    );
    expect(reasonOf(() => verifyChainKeyProof(extra, walkFor()))).toBe('schema');
    // ...and the signature, against the key the payload names.
    const mismatched = forge({ alg: 'EdDSA', typ: KEY_ADD_JWS_TYP }, vectorPayload(), OTHER_SEED);
    expect(reasonOf(() => verifyChainKeyProof(mismatched, walkFor()))).toBe('signature');
  });

  it('refuses an EMPTY expectedTyp as a MISCONFIGURATION, like the presentation mode', () => {
    expect(() => verifyChainKeyProof(VECTOR_JWS, walkFor({ expectedTyp: '' }))).toThrow(
      /registered purpose value/,
    );
  });
});
