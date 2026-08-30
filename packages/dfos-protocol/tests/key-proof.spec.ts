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
  keyProofSigningInput,
  KeyProofVerifyError,
  MAX_KEY_PROOF_SIZE,
  signKeyProof,
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
const VECTOR_TIMESTAMP = '2026-03-07T00:00:00.000Z';
/** Unix seconds of VECTOR_TIMESTAMP — the instant a verifier's clock is pinned to. */
const VECTOR_UNIX = 1772841600;
const VECTOR_MULTIBASE = 'z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2';
const OTHER_MULTIBASE = 'z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG';

const VECTOR_CANONICAL =
  '{"nonce":"nonce-key-proof-vector-0001","audience":"keys.dfos.com","publicKeyMultibase":"z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2","timestamp":"2026-03-07T00:00:00.000Z"}';
const VECTOR_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.r7fDOdNq04g6BDaQpeuVbQ0mvcJ3OV2fBkNqd7kNKkZLRFnoa5ktLZDs-Ef-qqFRqwpK0bbUT827Fv7A5ZPICA';

/** The SAME fixture under a second purpose — the proof that `typ` is a parameter. */
const VECTOR_OTHER_TYP = 'did:dfos:key-proof-vector-other';
const VECTOR_OTHER_TYP_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1wcm9vZi12ZWN0b3Itb3RoZXIifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.NMNjktabEWgXRhP28Jh2hLl7s6ATWD4liXvS_nw85HwvnLu14HEl6NINtuTSO2O2dBW7tPOcnJrvFSrnrzPRDA';

/**
 * THE MALLEABILITY NEGATIVES. Both carry the vector's exact four members, both
 * are REALLY signed by the vector key over the octets they present, and both are
 * refused: the first serializes the members in reverse order, the second inserts
 * insignificant whitespace. A signature covers whatever octets arrived, so the
 * only thing that makes one proof one string is the verifier recomputing the
 * canonical signing input and byte-comparing. Pinned in key_proof_test.go too —
 * a twin that accepted either would be accepting bytes production refuses.
 */
const VECTOR_REORDERED_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJhdWRpZW5jZSI6ImtleXMuZGZvcy5jb20iLCJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSJ9.Xnigl9DVx4IMKoFypxcfJqZig9M7KSQUrfk-7Is46ZEOF4jML0tf_hePFrv596FPWmFn02q7hMhSQhtxpdDpCA';
const VECTOR_SPACED_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6ICJub25jZS1rZXktcHJvb2YtdmVjdG9yLTAwMDEiLCAiYXVkaWVuY2UiOiAia2V5cy5kZm9zLmNvbSIsICJwdWJsaWNLZXlNdWx0aWJhc2UiOiAiejZNa2hGd1hORldvc0xldWd2U2Y0d2NMOXQzdXVSWHVlR1NGVFJnU3ZIaFdqNUcyIiwgInRpbWVzdGFtcCI6ICIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.PwFg4KJcHQ6dsj0zEeeuHJTn-KKSfZXXciCI8PGE8OL9DZHMCROWaYB0pBhHMyUuQsvh3iUM3U9_JvrmpzzBDg';

/** The same members signed by the OTHER key, naming the OTHER key. */
const VECTOR_OTHER_KEY_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtneGoyUjNITHRRUnBQbnZmdnB1S0VjZVNxZjN0WkhCamRtWjNmRnozSkhHRyIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.p1pM7ycrLvynxbrHSCAJZiWIw5RufHWnnQa-ewpj8SbOI55o01IfV2-SO4rs28SqTa40WeLQovyE4TqI1_PQDQ';

const vectorPayload = (): KeyProofPayload => ({
  nonce: VECTOR_NONCE,
  audience: VECTOR_AUDIENCE,
  publicKeyMultibase: VECTOR_MULTIBASE,
  timestamp: VECTOR_TIMESTAMP,
});

const at = (unixSeconds: number) => () => unixSeconds * 1000;

const expectAt = (overrides: Partial<Parameters<typeof verifyKeyProof>[1]> = {}) => ({
  expectedTyp: KEY_ADD_JWS_TYP,
  expectedAudience: VECTOR_AUDIENCE,
  now: at(VECTOR_UNIX),
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
      audience: a.audience,
      nonce: a.nonce,
    };
    expect(keyProofSigningInput(b)).toEqual(keyProofSigningInput(a));
  });

  it('derives publicKeyMultibase from the private key and pins the signed vector', async () => {
    const { proof, payload } = await signKeyProof({
      typ: KEY_ADD_JWS_TYP,
      nonce: VECTOR_NONCE,
      audience: VECTOR_AUDIENCE,
      privateKey: VECTOR_SEED,
      timestamp: VECTOR_TIMESTAMP,
    });
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
    const { proof } = await signKeyProof({
      typ: VECTOR_OTHER_TYP,
      nonce: VECTOR_NONCE,
      audience: VECTOR_AUDIENCE,
      privateKey: VECTOR_SEED,
      timestamp: VECTOR_TIMESTAMP,
    });
    expect(proof).toBe(VECTOR_OTHER_TYP_JWS);
    // Same payload segment as the key-add vector: only the header differs.
    expect(proof.split('.')[1]).toBe(VECTOR_JWS.split('.')[1]);
  });

  it('floor-normalizes a millisecond-bearing timestamp, and defaults to now', async () => {
    const floored = await signKeyProof({
      typ: KEY_ADD_JWS_TYP,
      nonce: VECTOR_NONCE,
      audience: VECTOR_AUDIENCE,
      privateKey: VECTOR_SEED,
      timestamp: '2026-03-07T00:00:00.987Z',
    });
    expect(floored.payload.timestamp).toBe(VECTOR_TIMESTAMP);
    expect(floored.proof).toBe(VECTOR_JWS);

    const defaulted = await signKeyProof({
      typ: KEY_ADD_JWS_TYP,
      nonce: VECTOR_NONCE,
      audience: VECTOR_AUDIENCE,
      privateKey: VECTOR_SEED,
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
      await expect(
        signKeyProof({
          typ: KEY_ADD_JWS_TYP,
          nonce: VECTOR_NONCE,
          audience: VECTOR_AUDIENCE,
          privateKey: VECTOR_SEED,
          timestamp,
        }),
      ).rejects.toThrow(/unparseable timestamp/);
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
      signKeyProof({
        typ: KEY_ADD_JWS_TYP,
        nonce: 'n'.repeat(MAX_KEY_PROOF_SIZE),
        audience: VECTOR_AUDIENCE,
        privateKey: VECTOR_SEED,
        timestamp: VECTOR_TIMESTAMP,
      }),
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
    // audience, fresh timestamp, exactly the four members. What fails is that the
    // presented octets are not the canonical serialization of those members. Left
    // unchecked, one proof would have unboundedly many spellings — and this
    // package would verify envelopes the platform's verifier already refuses.
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
    for (const member of ['nonce', 'audience', 'publicKeyMultibase', 'timestamp'] as const) {
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
    await expect(
      signKeyProof({
        typ: '',
        nonce: VECTOR_NONCE,
        audience: VECTOR_AUDIENCE,
        privateKey: VECTOR_SEED,
        timestamp: VECTOR_TIMESTAMP,
      }),
    ).rejects.toThrow(/registered purpose value/);

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
