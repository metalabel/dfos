import { describe, expect, it } from 'vitest';
import {
  assertCanonicalSignRequestPayload,
  buildSignRequest,
  CreditClaimVerifyError,
  encodeEd25519Multikey,
  MAX_SIGN_REQUEST_PAYLOAD_SIZE,
  MAX_SIGN_REQUEST_SIZE,
  signCreditClaim,
  SignRequestVerifyError,
  verifyCreditClaim,
  verifySignRequest,
} from '../src/chain';
import type { MultikeyPublicKey, VerifiedIdentity } from '../src/chain';
import {
  createJws,
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

// =============================================================================
// helpers
// =============================================================================

const encoder = new TextEncoder();

const multikey = (keyId: string, publicKey: Uint8Array): MultikeyPublicKey => ({
  id: keyId,
  type: 'Multikey',
  publicKeyMultibase: encodeEd25519Multikey(publicKey),
});

const makeParty = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (message: Uint8Array) => signPayloadEd25519(message, keypair.privateKey);
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    authKeys: [multikey(keyId, keypair.publicKey)],
    assertKeys: [],
    controllerKeys: [],
    services: [],
  };
  return { keypair, keyId, did, kid, signer, identity };
};

type Party = ReturnType<typeof makeParty>;

const resolverFor = (...identities: VerifiedIdentity[]) => {
  const byDid = new Map(identities.map((identity) => [identity.did, identity]));
  return async (did: string) => byDid.get(did);
};

const throwingResolver = async (): Promise<VerifiedIdentity | undefined> => {
  throw new Error('relay unreachable');
};

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

const signArbitrary = async (party: Party, header: unknown, payload: unknown): Promise<string> => {
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signature = await party.signer(encoder.encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
};

const signRaw = async (
  party: Party,
  payload: Record<string, unknown>,
  overrides: { typ?: string; kid?: string; cid?: string; header?: Record<string, unknown> } = {},
) => {
  const encoded = await dagCborCanonicalEncode(payload);
  const header = {
    alg: 'EdDSA',
    typ: overrides.typ ?? 'did:dfos:sign-request',
    kid: overrides.kid ?? party.kid,
    cid: overrides.cid ?? encoded.cid.toString(),
    ...overrides.header,
  };
  return createJws({
    header: header as Parameters<typeof createJws>[0]['header'],
    payload,
    sign: party.signer,
  });
};

const baseEnvelope = (party: Party, overrides: Record<string, unknown> = {}) => ({
  version: 1,
  type: 'sign-request',
  did: party.did,
  subject: makeParty().did,
  payloadTyp: 'did:dfos:credit-claim',
  payload: Buffer.from('target bytes', 'utf8').toString('base64url'),
  createdAt: '2026-08-10T00:00:00.000Z',
  expiresAt: '2026-08-11T00:00:00.000Z',
  ...overrides,
});

const expectVerdict = async (promise: Promise<unknown>, reason: 'invalid' | 'unverifiable') => {
  const error = await promise.then(
    () => {
      throw new Error('expected verification to reject');
    },
    (thrown: unknown) => thrown,
  );
  expect(error).toBeInstanceOf(SignRequestVerifyError);
  expect((error as SignRequestVerifyError).reason).toBe(reason);
};

const verifyAt = (token: string, identities: VerifiedIdentity[]) =>
  verifySignRequest(token, {
    resolveIdentity: resolverFor(...identities),
    now: Date.parse('2026-08-10T12:00:00.000Z'),
  });

const parityClaimBytes = encoder.encode(
  '{"version":1,"type":"credit-claim","contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae","role":"photography","createdAt":"2026-08-10T00:00:00.000Z"}',
);

// =============================================================================
// envelope
// =============================================================================

describe('sign request envelope', () => {
  it('round-trips exact bytes and is deterministic with fixed timestamps', async () => {
    const requester = makeParty();
    const subject = makeParty();
    const payload = Uint8Array.from([0, 1, 2, 127, 128, 255]);
    const input = {
      did: requester.did,
      subject: subject.did,
      payloadTyp: 'did:dfos:credit-claim',
      payload,
      createdAt: '2026-08-10T00:00:00.777Z',
      expiresAt: '2026-08-11T00:00:00.999Z',
      signer: requester.signer,
      keyId: requester.keyId,
    };

    const first = await buildSignRequest(input);
    const second = await buildSignRequest(input);
    expect(second).toEqual(first);

    const verified = await verifyAt(first.jwsToken, [requester.identity]);
    expect(verified).toMatchObject({
      did: requester.did,
      subject: subject.did,
      payloadTyp: 'did:dfos:credit-claim',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-11T00:00:00.000Z',
      signerKeyId: requester.kid,
      requestCID: first.requestCID,
    });
    expect(verified.payloadBytes).toEqual(payload);
  });

  it('derives the normative cross-language parity CID', async () => {
    // The Go twin (sign_request_test.go, TestSignRequestCIDParityVector) encodes
    // this same fixed payload and MUST derive this exact CID. A divergence forks
    // request identity — so this literal is normative, not a snapshot to re-bless.
    const payload = {
      version: 1,
      type: 'sign-request',
      did: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
      subject: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
      payloadTyp: 'did:dfos:credit-claim',
      payload: Buffer.from(parityClaimBytes).toString('base64url'),
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-13T00:00:00.000Z',
    };
    const encoded = await dagCborCanonicalEncode(payload);
    expect(encoded.cid.toString()).toBe(
      'bafyreibl3vv5shcpzvm5kyntihs5y22sxykqgju6c3iuw7hybhudktpisu',
    );
  });

  it('enforces build-path payload, temporal, and token caps', async () => {
    const requester = makeParty();
    const subject = makeParty();
    const common = {
      did: requester.did,
      subject: subject.did,
      payloadTyp: 'did:dfos:credit-claim',
      createdAt: '2026-08-10T00:00:00.000Z',
      signer: requester.signer,
      keyId: requester.keyId,
    };

    await expect(
      buildSignRequest({ ...common, payload: new Uint8Array(), expiresAt: '2026-08-11T00:00:00Z' }),
    ).rejects.toThrow('non-empty');
    await expect(
      buildSignRequest({
        ...common,
        payload: new Uint8Array(MAX_SIGN_REQUEST_PAYLOAD_SIZE + 1),
        expiresAt: '2026-08-11T00:00:00Z',
      }),
    ).rejects.toThrow('max decoded size');
    await expect(
      buildSignRequest({
        ...common,
        payload: encoder.encode('x'),
        expiresAt: '2026-08-10T00:00:00Z',
      }),
    ).rejects.toThrow('strictly after');
    await expect(
      buildSignRequest({
        ...common,
        payload: encoder.encode('x'),
        expiresAt: '2026-08-17T00:00:01Z',
      }),
    ).rejects.toThrow('604800');
    await expect(
      buildSignRequest({
        ...common,
        subject: `did:${'x'.repeat(MAX_SIGN_REQUEST_SIZE)}`,
        payload: encoder.encode('x'),
        expiresAt: '2026-08-11T00:00:00Z',
      }),
    ).rejects.toThrow('exceeds max size');
  });

  it('rejects oversized and malformed tokens before verification', async () => {
    const requester = makeParty();
    await expectVerdict(
      verifyAt('x'.repeat(MAX_SIGN_REQUEST_SIZE + 1), [requester.identity]),
      'invalid',
    );
    await expectVerdict(verifyAt('not-a-jws', [requester.identity]), 'invalid');
  });

  it('rejects malformed header shapes and every profile violation', async () => {
    const requester = makeParty();
    const payload = baseEnvelope(requester);
    const cid = (await dagCborCanonicalEncode(payload)).cid.toString();
    const headers: unknown[] = [
      null,
      [],
      { alg: 'EdDSA', typ: 'did:dfos:sign-request', cid },
      { alg: 'EdDSA', typ: 'did:dfos:sign-request', kid: 42, cid },
      { alg: 'EdDSA', kid: requester.kid, cid },
      { alg: 'none', typ: 'did:dfos:sign-request', kid: requester.kid, cid },
      { alg: 'EdDSA', typ: 'did:dfos:sign-request', kid: requester.kid, cid, crit: [] },
      { alg: 'EdDSA', typ: 'did:dfos:sign-request', kid: requester.kid, cid, jwk: {} },
      { alg: 'EdDSA', typ: 'did:dfos:sign-request', kid: requester.kid, cid, x5c: [] },
    ];
    for (const header of headers) {
      await expectVerdict(
        verifyAt(await signArbitrary(requester, header, payload), [requester.identity]),
        'invalid',
      );
    }
  });

  it('rejects wrong typ, kid mismatch, decoy CID, and wrong signature bytes', async () => {
    const requester = makeParty();
    const other = makeParty();
    const payload = baseEnvelope(requester);

    await expectVerdict(
      verifyAt(await signRaw(requester, payload, { typ: 'did:dfos:credit-claim' }), [
        requester.identity,
      ]),
      'invalid',
    );
    await expectVerdict(
      verifyAt(await signRaw(other, payload), [requester.identity, other.identity]),
      'invalid',
    );
    const decoy = await dagCborCanonicalEncode({ ...payload, subject: other.did });
    await expectVerdict(
      verifyAt(await signRaw(requester, payload, { cid: decoy.cid.toString() }), [
        requester.identity,
      ]),
      'invalid',
    );

    const good = await signRaw(requester, payload);
    const swapped: VerifiedIdentity = {
      ...requester.identity,
      authKeys: [multikey(requester.keyId, other.keypair.publicKey)],
    };
    await expectVerdict(verifyAt(good, [swapped]), 'invalid');
  });

  it('rejects every temporal boundary and overlong window', async () => {
    const requester = makeParty();
    const cases = [
      baseEnvelope(requester, { expiresAt: '2026-08-10T00:00:00.000Z' }),
      baseEnvelope(requester, { expiresAt: '2026-08-09T23:59:59.000Z' }),
      baseEnvelope(requester, { expiresAt: '2026-08-17T00:00:01.000Z' }),
    ];
    for (const payload of cases) {
      await expectVerdict(
        verifyAt(await signRaw(requester, payload), [requester.identity]),
        'invalid',
      );
    }

    const expiresAt = '2026-08-11T00:00:00.000Z';
    const token = await signRaw(requester, baseEnvelope(requester, { expiresAt }));
    await expectVerdict(
      verifySignRequest(token, {
        resolveIdentity: resolverFor(requester.identity),
        now: Date.parse(expiresAt),
      }),
      'invalid',
    );
  });

  it('rejects non-canonical, empty, and oversized target-byte encodings', async () => {
    const requester = makeParty();
    const encodings = [
      'eA==',
      'eA+',
      '',
      Buffer.alloc(MAX_SIGN_REQUEST_PAYLOAD_SIZE + 1).toString('base64url'),
    ];
    for (const payloadEncoding of encodings) {
      const token = await signRaw(requester, baseEnvelope(requester, { payload: payloadEncoding }));
      await expectVerdict(verifyAt(token, [requester.identity]), 'invalid');
    }
  });

  it('keeps unresolvable and throwing resolution distinct from invalid requests', async () => {
    const requester = makeParty();
    const token = await signRaw(requester, baseEnvelope(requester));
    await expectVerdict(verifyAt(token, []), 'unverifiable');
    await expectVerdict(
      verifySignRequest(token, {
        resolveIdentity: throwingResolver,
        now: Date.parse('2026-08-10T12:00:00.000Z'),
      }),
      'unverifiable',
    );

    const deleted: VerifiedIdentity = { ...requester.identity, isDeleted: true };
    await expectVerdict(verifyAt(token, [deleted]), 'invalid');
  });
});

// =============================================================================
// signer-side canonicalization
// =============================================================================

describe('sign request canonical payload check', () => {
  const subject = 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae';
  const bare =
    '{"version":1,"type":"credit-claim","contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae","role":"photography","createdAt":"2026-08-10T00:00:00.000Z"}';
  const withAsOf = bare.replace(
    '}',
    ',"asOfDocumentCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"}',
  );
  const check = (source: string, typ = 'did:dfos:credit-claim', expectedSubject = subject) =>
    assertCanonicalSignRequestPayload(typ, encoder.encode(source), { subject: expectedSubject });

  it('accepts exact canonical credit-claim bytes with and without asOfDocumentCID', () => {
    expect(() => check(bare)).not.toThrow();
    expect(() => check(withAsOf)).not.toThrow();

    const special = bare.replace('photography', '<photography>&é\u2028');
    expect(() => check(special)).not.toThrow();

    // A role legitimately containing the six literal chars ` ` canonicalizes
    // to `\\u2028` (escaped backslash) and must round-trip — exactly the value a
    // blind post-substitution on the Go side would corrupt.
    const literalEscape = bare.replace('photography', 'a\\\\u2028b');
    expect(() => check(literalEscape)).not.toThrow();
  });

  it('refuses a lone surrogate in role (no convergent canonical form)', () => {
    const loneSurrogate = bare.replace('photography', '\\ud800');
    expect(() => check(loneSurrogate)).toThrow(SignRequestVerifyError);
  });

  it('refuses the shared adversarial canonicalization vectors', () => {
    const adversarial = [
      bare.replace('"version":1', '"version": 1'),
      bare.replace('"role":"photography"', '"role":"editor","role":"photography"'),
      bare.replace(
        '"contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"',
        '"did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae","contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z"',
      ),
      bare.replace('"version":1', '"version":1.0'),
      bare.replace('"version":1', '"version":1e0'),
      bare.replace('photography', 'photograph\\u0079'),
      bare.replace('}', ',"note":"hi"}'),
      bare.replace('.000Z', '.123Z'),
      bare.replace(subject, 'did:dfos:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
      withAsOf.replace('bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne', ''),
      `${bare}\n`,
      `\uFEFF${bare}`,
      '[]',
      '42',
      '"x"',
    ];
    for (const source of adversarial) {
      expect(() => check(source), source).toThrow(SignRequestVerifyError);
    }
    expect(() => check(bare, 'did:dfos:credential')).toThrow(/did:dfos:credential/);
  });

  it('admits bytes the credit-claim artifact family verifies end to end', async () => {
    const claimant = makeParty();
    const canonical = bare.replaceAll(subject, claimant.did);
    assertCanonicalSignRequestPayload('did:dfos:credit-claim', encoder.encode(canonical), {
      subject: claimant.did,
    });

    const { jwsToken } = await signCreditClaim({
      contentId: 'cv7n8vkvr64cctf3294h9k4eanhff8z',
      did: claimant.did,
      role: 'photography',
      createdAt: '2026-08-10T00:00:00.000Z',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });
    expect(Buffer.from(jwsToken.split('.')[1]!, 'base64url')).toEqual(Buffer.from(canonical));
    await expect(
      verifyCreditClaim(jwsToken, {
        resolveIdentity: resolverFor(claimant.identity),
        expectedContentId: 'cv7n8vkvr64cctf3294h9k4eanhff8z',
      }),
    ).resolves.not.toThrow();
  });

  it('returns structured invalid refusals', () => {
    try {
      check('{}');
      throw new Error('expected refusal');
    } catch (error) {
      expect(error).toBeInstanceOf(SignRequestVerifyError);
      expect((error as SignRequestVerifyError).reason).toBe('invalid');
      expect(error).not.toBeInstanceOf(CreditClaimVerifyError);
    }
  });
});
