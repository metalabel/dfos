import { describe, expect, it } from 'vitest';
import { encodeEd25519Multikey } from '../src/chain';
import type { VerifiedIdentity } from '../src/chain';
import {
  apiIdentitySigningInput,
  ApiRequestVerifyError,
  createDFOSCredential,
  CredentialVerificationError,
  decodeDFOSCredentialUnsafe,
  EMPTY_BODY_SHA256,
  IDENTITY_PROOF_JWS_TYP,
  isAttenuated,
  matchesResource,
  MAX_REQUEST_PROOF_SIZE,
  parseDfosAuthorization,
  signApiIdentityRequest,
  signApiRequest,
  verifyDelegationChain,
  verifyDFOSCredential,
  verifyIdentityProofEnvelope,
  verifyRequestProofEnvelope,
  type ProofEnvelopeInput,
} from '../src/credentials';
import { base64urlEncode, createNewEd25519Keypair, generateId, signPayloadEd25519 } from '../src/crypto';

// =============================================================================
// helpers
// =============================================================================

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    authKeys: [
      { id: keyId, type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey) },
    ],
    assertKeys: [],
    controllerKeys: [],
    services: [],
  };
  return { keypair, keyId, did, kid, signer, identity };
};

const futureUnix = (minutes: number) => Math.floor(Date.now() / 1000) + minutes * 60;
const pastUnix = (minutes: number) => Math.floor(Date.now() / 1000) - minutes * 60;

// shared identity registry for resolveIdentity
const identityMap = new Map<string, VerifiedIdentity>();
const resolveIdentity = async (did: string) => identityMap.get(did);

// =============================================================================
// identity proof envelope (API-AUTH)
// =============================================================================

// The identity proof replaced the DID-signed auth-token JWT as the relay's (and
// every DFOS-gated surface's) AuthN artifact. Each case below carries forward a
// rule the auth-token suite asserted — expiry became the freshness window,
// audience became the host binding, kid/iss agreement became "the signer IS the
// principal" — plus the rules the envelope adds (typ scoping, the config
// verdict, additive members).

const proofPresenter = (id: ReturnType<typeof makeIdentity>, isDeleted = false) => ({
  isDeleted,
  keys: id.identity.authKeys,
});

const resolverFor =
  (states: Record<string, { isDeleted: boolean; keys: VerifiedIdentity['authKeys'] }>) =>
  async (did: string) =>
    states[did] ?? null;

const signIdentityProof = async (
  id: ReturnType<typeof makeIdentity>,
  overrides: Partial<Parameters<typeof signApiIdentityRequest>[0]> = {},
) =>
  signApiIdentityRequest({
    method: 'GET',
    host: 'relay.example.com',
    path: '/signing/v0/requests',
    kid: id.kid,
    sign: id.signer,
    ...overrides,
  });

const expectations = (overrides: Partial<ProofEnvelopeInput> = {}): ProofEnvelopeInput => ({
  proof: '',
  method: 'GET',
  host: 'relay.example.com',
  path: '/signing/v0/requests',
  ...overrides,
});

describe('identity proof envelope', () => {
  it('should create and verify round-trip', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    const verified = await verifyIdentityProofEnvelope(
      expectations({ proof }),
      resolverFor({ [id.did]: proofPresenter(id) }),
    );
    expect(verified.presenterDID).toBe(id.did);
    expect(verified.kid).toBe(id.kid);
    expect(verified.payload.host).toBe('relay.example.com');
  });

  // The auth token's `exp` is gone: the VERIFIER owns the freshness window, so
  // a presenter can never widen its own replay window.
  it('should reject a proof older than the acceptance window', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id, { iat: pastUnix(5) });
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', phase: 'proof', status: 401 });
  });

  // The auth token's `aud` became the host binding — and the value compared
  // against is the VERIFIER'S OWN configured authority, never a request header.
  it('should reject a host mismatch', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id, { host: 'other.example.com' });
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should reject a method or path mismatch — the proof binds ONE request', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof, method: 'POST' }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof, path: '/signing/v0/requests?limit=1' }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should reject a body-hash mismatch', async () => {
    const id = makeIdentity();
    const body = new TextEncoder().encode('{"operations":[]}');
    const { proof } = await signIdentityProof(id, { method: 'POST', path: '/x', body });
    await expect(
      verifyIdentityProofEnvelope(
        expectations({
          proof,
          method: 'POST',
          path: '/x',
          body: new TextEncoder().encode('{"operations":["a"]}'),
        }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should reject a wrong signing key', async () => {
    const id = makeIdentity();
    const other = makeIdentity();
    const { proof } = await signIdentityProof(id);
    // Same kid, a DIFFERENT key registered as current state → signature fails.
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({
          [id.did]: { isDeleted: false, keys: [{ ...other.identity.authKeys[0]!, id: id.keyId }] },
        }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should reject a key that is not in the presenter CURRENT state', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: { isDeleted: false, keys: [] } }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should reject kid without DID URL format', async () => {
    const id = makeIdentity();
    await expect(signIdentityProof(id, { kid: 'not-a-did-url' })).rejects.toThrow(
      'kid must be a DID URL',
    );
  });

  // The auth token asserted kid-DID === iss. The identity proof has no `iss`:
  // THE SIGNER IS THE PRINCIPAL, so the two can no longer disagree — and the
  // rule that replaces it is the deleted-presenter off-switch.
  it('should reject a deleted presenter (401 — checked and failed)', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: proofPresenter(id, true) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should report an unresolvable presenter as unverifiable (503, not 401)', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    await expect(
      verifyIdentityProofEnvelope(expectations({ proof }), resolverFor({})),
    ).rejects.toMatchObject({ reason: 'unverifiable', phase: 'proof', status: 503 });
  });

  it('should respect the now() override', async () => {
    const id = makeIdentity();
    const iat = pastUnix(120);
    const { proof } = await signIdentityProof(id, { iat });
    const verified = await verifyIdentityProofEnvelope(
      expectations({ proof, now: () => iat * 1000 }),
      resolverFor({ [id.did]: proofPresenter(id) }),
    );
    expect(verified.payload.iat).toBe(iat);
  });

  it('should reject a proof forward-dated beyond the clock-skew allowance', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id, { iat: futureUnix(5) });
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should throw ApiRequestVerifyError on an invalid payload', async () => {
    const id = makeIdentity();
    // A hand-built proof whose payload fails the step-3 schema (iat <= 0).
    const header = base64urlEncode(
      JSON.stringify({ alg: 'EdDSA', typ: IDENTITY_PROOF_JWS_TYP, kid: id.kid }),
    );
    const payload = base64urlEncode(
      JSON.stringify({
        method: 'GET',
        host: 'relay.example.com',
        path: '/signing/v0/requests',
        bodyHash: EMPTY_BODY_SHA256,
        iat: 0,
      }),
    );
    const signingInput = `${header}.${payload}`;
    const signature = base64urlEncode(
      await id.signer(new TextEncoder().encode(signingInput)),
    );
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof: `${signingInput}.${signature}` }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toBeInstanceOf(ApiRequestVerifyError);
  });

  it('should ignore unknown members (forward-compat, MUST-ignore-unknown)', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id, {
      extraMembers: { 'x-future': 'whatever' },
    });
    const verified = await verifyIdentityProofEnvelope(
      expectations({ proof }),
      resolverFor({ [id.did]: proofPresenter(id) }),
    );
    expect(verified.presenterDID).toBe(id.did);
    expect(verified.rawPayload['x-future']).toBe('whatever');
  });

  // --- typ scoping, both directions ---

  it('should reject a request proof presented where an identity proof is required', async () => {
    const id = makeIdentity();
    const { proof } = await signApiRequest({
      method: 'GET',
      host: 'relay.example.com',
      path: '/signing/v0/requests',
      credentialCID: 'bafyreiexample',
      kid: id.kid,
      sign: id.signer,
    });
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  it('should reject an identity proof presented where a request proof is required', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    await expect(
      verifyRequestProofEnvelope(
        expectations({ proof }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'invalid', status: 401 });
  });

  // --- the config verdict, and its ORDER ---

  it('should report a W + S over the ceiling as config (500), not invalid', async () => {
    const id = makeIdentity();
    const { proof } = await signIdentityProof(id);
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof, windowSeconds: 200, skewSeconds: 200 }),
        resolverFor({ [id.did]: proofPresenter(id) }),
      ),
    ).rejects.toMatchObject({ reason: 'config', phase: 'config', status: 500 });
  });

  it('should report config BEFORE the token-size gate — request data never masks a deployment bug', async () => {
    const oversized = 'a'.repeat(MAX_REQUEST_PROOF_SIZE + 1);
    await expect(
      verifyIdentityProofEnvelope(
        expectations({ proof: oversized, windowSeconds: 200, skewSeconds: 200 }),
        resolverFor({}),
      ),
    ).rejects.toMatchObject({ reason: 'config', status: 500 });
  });

  // --- additive members (the jti seam) ---

  it('should append additive members AFTER the canonical order', () => {
    const payload = {
      method: 'POST',
      host: 'relay.example.com',
      path: '/proof/v1/operations',
      bodyHash: EMPTY_BODY_SHA256,
      iat: 1772841600,
    };
    const bytes = new TextDecoder().decode(
      apiIdentitySigningInput(payload, { jti: 'jti-fixed-0001' }),
    );
    expect(bytes).toBe(
      '{"method":"POST","host":"relay.example.com","path":"/proof/v1/operations",' +
        `"bodyHash":"${EMPTY_BODY_SHA256}","iat":1772841600,"jti":"jti-fixed-0001"}`,
    );
  });

  it('should order additive members lexicographically, not by insertion', () => {
    const payload = {
      method: 'POST',
      host: 'relay.example.com',
      path: '/proof/v1/operations',
      bodyHash: EMPTY_BODY_SHA256,
      iat: 1772841600,
    };
    const one = apiIdentitySigningInput(payload, { zeta: 'z', alpha: 'a' });
    const two = apiIdentitySigningInput(payload, { alpha: 'a', zeta: 'z' });
    expect(new TextDecoder().decode(one)).toBe(new TextDecoder().decode(two));
    expect(new TextDecoder().decode(one)).toContain('"alpha":"a","zeta":"z"}');
  });

  it('should refuse an additive member that shadows a canonical one', () => {
    expect(() =>
      apiIdentitySigningInput(
        {
          method: 'GET',
          host: 'relay.example.com',
          path: '/x',
          bodyHash: EMPTY_BODY_SHA256,
          iat: 1772841600,
        },
        { iat: '1' },
      ),
    ).toThrow('canonical member');
  });

  it('should emit a payload segment equal to the canonical signing input', async () => {
    const id = makeIdentity();
    const { proof, payload } = await signIdentityProof(id, {
      iat: 1772841600,
      extraMembers: { jti: 'jti-fixed-0001' },
    });
    const segment = proof.split('.')[1]!;
    expect(segment).toBe(
      base64urlEncode(apiIdentitySigningInput(payload, { jti: 'jti-fixed-0001' })),
    );
  });
});

// =============================================================================
// the DFOS authorization scheme
// =============================================================================

describe('parseDfosAuthorization', () => {
  it('matches the scheme case-insensitively and returns the bare token', () => {
    expect(parseDfosAuthorization('DFOS abc.def.ghi')).toBe('abc.def.ghi');
    expect(parseDfosAuthorization('dfos abc.def.ghi')).toBe('abc.def.ghi');
    expect(parseDfosAuthorization('  Dfos   abc.def.ghi  ')).toBe('abc.def.ghi');
  });

  it('refuses every other scheme — Bearer is not this family', () => {
    expect(parseDfosAuthorization('Bearer abc.def.ghi')).toBeNull();
    expect(parseDfosAuthorization('DFOS')).toBeNull();
    expect(parseDfosAuthorization('DFOS ')).toBeNull();
    expect(parseDfosAuthorization(undefined)).toBeNull();
  });
});

// =============================================================================
// DFOS credentials
// =============================================================================

describe('dfos credential', () => {
  // --- create / verify round-trip ---

  it('should create and verify round-trip', async () => {
    const issuer = makeIdentity();
    const target = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: target.did,
      att: [{ resource: 'chain:content123', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    const verified = await verifyDFOSCredential(token, { resolveIdentity });

    expect(verified.iss).toBe(issuer.did);
    expect(verified.aud).toBe(target.did);
    expect(verified.att).toEqual([{ resource: 'chain:content123', action: 'write' }]);
    expect(verified.prf).toEqual([]);
    expect(verified.credentialCID).toBeTruthy();
    expect(verified.signerKeyId).toBe(issuer.kid);
  });

  // --- verification failures ---

  it('should reject verification with wrong key', async () => {
    const issuer = makeIdentity();
    const wrong = makeIdentity();
    // register identity with issuer's DID and key ID but wrong public key bytes
    identityMap.set(issuer.did, {
      did: issuer.did,
      isDeleted: false,
      authKeys: [
        {
          id: issuer.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(wrong.keypair.publicKey),
        },
      ],
      assertKeys: [],
      controllerKeys: [],
      services: [],
    });

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity })).rejects.toThrow(/signature/i);

    // clean up
    identityMap.delete(issuer.did);
  });

  it('should reject expired credential', async () => {
    const issuer = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: pastUnix(5),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity })).rejects.toThrow(/expired/i);
  });

  it('should reject an over-size credential token (DoS guard, before decode)', async () => {
    // the leaf token embeds the whole nested delegation chain, so one size cap
    // bounds the entire chain; the check fires before any decode.
    const oversize = 'x'.repeat(262145);
    await expect(verifyDFOSCredential(oversize, { resolveIdentity })).rejects.toThrow(
      /exceeds max size/,
    );
  });

  it('should reject credential not yet valid (iat in future)', async () => {
    const issuer = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: 20000,
      iat: 15000,
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity, now: 10000 })).rejects.toThrow(
      /not yet valid/i,
    );
  });

  // --- delegation chains ---

  it('should verify a 2-hop delegation chain (space -> member)', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);

    // root credential: space -> member
    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: space.signer,
      keyId: space.keyId,
    });

    // leaf credential: member -> anyone, with parent proof
    const leafToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(30),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    const chain = await verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did });

    expect(chain.rootDID).toBe(space.did);
    expect(chain.chain).toHaveLength(2);
    expect(chain.credential.iss).toBe(member.did);
  });

  it('should verify a 3-hop delegation chain (space -> member -> device)', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    const device = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);
    identityMap.set(device.did, device.identity);

    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(120),
      signer: space.signer,
      keyId: space.keyId,
    });

    const midToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: device.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(60),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leafToken = await createDFOSCredential({
      issuerDID: device.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [midToken],
      exp: futureUnix(30),
      signer: device.signer,
      keyId: device.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    const chain = await verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did });

    expect(chain.rootDID).toBe(space.did);
    expect(chain.chain).toHaveLength(3);
  });

  it('should reject multi-parent credentials at construction (WP-4 MAX_PRF=1)', async () => {
    // The exploit linear delegation closes: an attacker holds a legit narrow
    // parent rooted at the real creator, self-issues a second parent granting
    // chain:* that roots only at themselves, and combines both under one leaf.
    // The old union model accepted the leaf because the union of parent att
    // covered the target while the root walk only followed the first parent.
    //
    // WP-4 pins MAX_PRF=1 in the schema, so a multi-parent credential can no
    // longer even be constructed — the spec's "reject prf>1" MUST is now
    // enforced at construction/decode, defense-in-depth ahead of the delegation
    // walk (which still rejects prf>1 if a token somehow bypasses the schema).
    const space = makeIdentity();
    const attacker = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(attacker.did, attacker.identity);

    const legitParent = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: attacker.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(120),
      signer: space.signer,
      keyId: space.keyId,
    });

    const selfParent = await createDFOSCredential({
      issuerDID: attacker.did,
      audienceDID: attacker.did,
      att: [{ resource: 'chain:*', action: 'write' }],
      prf: [],
      exp: futureUnix(120),
      signer: attacker.signer,
      keyId: attacker.keyId,
    });

    // constructing a multi-parent leaf is now rejected by the schema (MAX_PRF=1)
    await expect(
      createDFOSCredential({
        issuerDID: attacker.did,
        audienceDID: '*',
        att: [{ resource: 'chain:victim', action: 'write' }],
        prf: [legitParent, selfParent],
        exp: futureUnix(60),
        signer: attacker.signer,
        keyId: attacker.keyId,
      }),
    ).rejects.toThrow(/credential payload/);
  });

  // --- attenuation enforcement ---

  it('should accept child that narrows scope', () => {
    const parent = [
      { resource: 'chain:content1', action: 'write' },
      { resource: 'chain:content2', action: 'write' },
    ];
    const child = [{ resource: 'chain:content1', action: 'write' }];
    expect(isAttenuated(parent, child)).toBe(true);
  });

  it('should reject child that widens scope', () => {
    const parent = [{ resource: 'chain:content1', action: 'write' }];
    const child = [
      { resource: 'chain:content1', action: 'write' },
      { resource: 'chain:content2', action: 'write' },
    ];
    expect(isAttenuated(parent, child)).toBe(false);
  });

  it('should accept child with empty action elements (canonicalizes to parent set)', () => {
    // "write," canonicalizes to {write}; Go already dropped the empty element,
    // TS now converges — the attenuation verdict matches across implementations.
    const parent = [{ resource: 'chain:content1', action: 'write' }];
    const child = [{ resource: 'chain:content1', action: 'write,' }];
    expect(isAttenuated(parent, child)).toBe(true);
  });

  it('should attenuate non-chain resource types by exact byte equality only', () => {
    // mailbox:<id> (SIGNING 0.x) and any future non-chain form: same-string
    // coverage passes, and action narrowing still applies on the matched entry.
    const mailbox = 'mailbox:nzkf838efr424433rn2rzkdv8h7t9ae';
    expect(
      isAttenuated(
        [{ resource: mailbox, action: 'deposit' }],
        [{ resource: mailbox, action: 'deposit' }],
      ),
    ).toBe(true);
    expect(
      isAttenuated(
        [{ resource: mailbox, action: 'deposit,read' }],
        [{ resource: mailbox, action: 'deposit' }],
      ),
    ).toBe(true);
    // widening the action set on the same mailbox is refused
    expect(
      isAttenuated(
        [{ resource: mailbox, action: 'deposit' }],
        [{ resource: mailbox, action: 'deposit,read' }],
      ),
    ).toBe(false);
    // a different mailbox id is not covered
    expect(
      isAttenuated(
        [{ resource: mailbox, action: 'deposit' }],
        [{ resource: 'mailbox:cnnnft9f8a2rn938d6nkz38r847v2kr', action: 'deposit' }],
      ),
    ).toBe(false);
  });

  it('should treat the wildcard as a chain-only concept — literal elsewhere, never cross-type', () => {
    const mailbox = 'mailbox:nzkf838efr424433rn2rzkdv8h7t9ae';
    // mailbox:* does NOT cover a concrete mailbox — a literal '*' id covers only itself
    expect(
      isAttenuated(
        [{ resource: 'mailbox:*', action: 'deposit' }],
        [{ resource: mailbox, action: 'deposit' }],
      ),
    ).toBe(false);
    expect(
      isAttenuated(
        [{ resource: 'mailbox:*', action: 'deposit' }],
        [{ resource: 'mailbox:*', action: 'deposit' }],
      ),
    ).toBe(true);
    // coverage never crosses resource types, wildcard or not
    expect(
      isAttenuated(
        [{ resource: 'chain:*', action: 'deposit' }],
        [{ resource: mailbox, action: 'deposit' }],
      ),
    ).toBe(false);
    expect(
      isAttenuated(
        [{ resource: mailbox, action: 'write' }],
        [{ resource: 'chain:content1', action: 'write' }],
      ),
    ).toBe(false);
  });

  it('should treat an empty action set as granting nothing on matchesResource', async () => {
    // "," canonicalizes to {} — vacuously a subset on attenuation, but it covers
    // no concrete request, so the relay authorizes no operation.
    const att = [{ resource: 'chain:content1', action: ',' }];
    expect(await matchesResource(att, 'chain:content1', 'write')).toBe(false);
    expect(await matchesResource(att, 'chain:content1', 'read')).toBe(false);
  });

  it('should reject child that extends expiry in delegation chain', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);

    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(30),
      signer: space.signer,
      keyId: space.keyId,
    });

    // child has exp beyond parent
    const leafToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(120),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    await expect(
      verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did }),
    ).rejects.toThrow(/expiry/i);
  });

  // --- resource matching ---

  it('should match chain:X against chain:X', async () => {
    const att = [{ resource: 'chain:content1', action: 'write' }];
    expect(await matchesResource(att, 'chain:content1', 'write')).toBe(true);
  });

  it('should not match chain:X against chain:Y', async () => {
    const att = [{ resource: 'chain:content1', action: 'write' }];
    expect(await matchesResource(att, 'chain:content2', 'write')).toBe(false);
  });

  // --- public credentials ---

  it('should create and verify public credential with aud "*"', async () => {
    const issuer = makeIdentity();
    identityMap.set(issuer.did, issuer.identity);

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:pub1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    const verified = await verifyDFOSCredential(token, { resolveIdentity });
    expect(verified.aud).toBe('*');
    expect(verified.iss).toBe(issuer.did);
  });

  // --- decode unsafe ---

  it('should decode credential without verification via decodeDFOSCredentialUnsafe', async () => {
    const issuer = makeIdentity();

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    const decoded = decodeDFOSCredentialUnsafe(token);
    expect(decoded).not.toBeNull();
    expect(decoded!.header.typ).toBe('did:dfos:credential');
    expect(decoded!.header.kid).toBe(issuer.kid);
    expect(decoded!.payload.iss).toBe(issuer.did);
    expect(decoded!.payload.aud).toBe('*');
    expect(decoded!.payload.att).toEqual([{ resource: 'chain:abc', action: 'write' }]);
    expect(decoded!.header.cid).toBeTruthy();
  });

  it('should return null for malformed tokens via decodeDFOSCredentialUnsafe', () => {
    expect(decodeDFOSCredentialUnsafe('not-a-token')).toBeNull();
    expect(decodeDFOSCredentialUnsafe('a.b')).toBeNull();
    expect(decodeDFOSCredentialUnsafe('')).toBeNull();
  });

  // --- delegation failures ---

  it('should reject delegation gap (child iss does not match any parent aud)', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    const outsider = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);
    identityMap.set(outsider.did, outsider.identity);

    // root credential: space -> member
    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: space.signer,
      keyId: space.keyId,
    });

    // outsider tries to use root credential they are not audience of
    const leafToken = await createDFOSCredential({
      issuerDID: outsider.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(30),
      signer: outsider.signer,
      keyId: outsider.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    await expect(
      verifyDelegationChain(leaf, { resolveIdentity, rootDID: space.did }),
    ).rejects.toThrow(/delegation gap/i);
  });

  it('should reject delegation root mismatch', async () => {
    const space = makeIdentity();
    const member = makeIdentity();
    const wrongRoot = makeIdentity();
    identityMap.set(space.did, space.identity);
    identityMap.set(member.did, member.identity);

    // root credential issued by space
    const rootToken = await createDFOSCredential({
      issuerDID: space.did,
      audienceDID: member.did,
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [],
      exp: futureUnix(60),
      signer: space.signer,
      keyId: space.keyId,
    });

    const leafToken = await createDFOSCredential({
      issuerDID: member.did,
      audienceDID: '*',
      att: [{ resource: 'chain:content1', action: 'write' }],
      prf: [rootToken],
      exp: futureUnix(30),
      signer: member.signer,
      keyId: member.keyId,
    });

    const leaf = await verifyDFOSCredential(leafToken, { resolveIdentity });
    // verify against wrong root DID
    await expect(
      verifyDelegationChain(leaf, { resolveIdentity, rootDID: wrongRoot.did }),
    ).rejects.toThrow(/root/i);
  });

  it('should throw CredentialVerificationError on failures', async () => {
    const issuer = makeIdentity();
    const wrong = makeIdentity();
    identityMap.set(issuer.did, {
      did: issuer.did,
      isDeleted: false,
      authKeys: [
        {
          id: issuer.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(wrong.keypair.publicKey),
        },
      ],
      assertKeys: [],
      controllerKeys: [],
      services: [],
    });

    const token = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: futureUnix(60),
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    await expect(verifyDFOSCredential(token, { resolveIdentity })).rejects.toThrow(
      CredentialVerificationError,
    );

    identityMap.delete(issuer.did);
  });

  // --- chain:* wildcard attenuation ---

  it('should accept chain:X as attenuated from chain:*', () => {
    const parent = [{ resource: 'chain:*', action: 'read' }];
    const child = [{ resource: 'chain:content1', action: 'read' }];
    expect(isAttenuated(parent, child)).toBe(true);
  });

  it('should accept chain:* as attenuated from chain:* (exact match)', () => {
    const parent = [{ resource: 'chain:*', action: 'read' }];
    const child = [{ resource: 'chain:*', action: 'read' }];
    expect(isAttenuated(parent, child)).toBe(true);
  });

  it('should reject chain:* as attenuated from chain:X (widening)', () => {
    const parent = [{ resource: 'chain:content1', action: 'read' }];
    const child = [{ resource: 'chain:*', action: 'read' }];
    expect(isAttenuated(parent, child)).toBe(false);
  });

  // --- chain:* wildcard resource matching ---

  it('should match chain:* with read against chain:someId with read', async () => {
    const att = [{ resource: 'chain:*', action: 'read' }];
    expect(await matchesResource(att, 'chain:someId', 'read')).toBe(true);
  });

  it('should not match chain:* with read against chain:someId with write (action mismatch)', async () => {
    const att = [{ resource: 'chain:*', action: 'read' }];
    expect(await matchesResource(att, 'chain:someId', 'write')).toBe(false);
  });
});
