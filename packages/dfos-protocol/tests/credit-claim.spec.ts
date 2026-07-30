import { describe, expect, it } from 'vitest';
import {
  CreditClaimPayload,
  CreditClaimVerifyError,
  encodeEd25519Multikey,
  MAX_CREDIT_CLAIM_SIZE,
  signCreditClaim,
  verifyCreditClaim,
  verifyCreditEntry,
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

const multikey = (keyId: string, publicKey: Uint8Array): MultikeyPublicKey => ({
  id: keyId,
  type: 'Multikey',
  publicKeyMultibase: encodeEd25519Multikey(publicKey),
});

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    assertKeys: [multikey(keyId, keypair.publicKey)],
    authKeys: [],
    controllerKeys: [],
    services: [],
  };
  return { keypair, keyId, did, kid, signer, identity };
};

/** A bare 31-char content chain id, the shape signCreditClaim binds to */
const makeContentId = () => generateId('test').substring(5);

const resolverFor = (...identities: VerifiedIdentity[]) => {
  const map = new Map(identities.map((i) => [i.did, i]));
  return async (did: string) => map.get(did);
};

/** Stands in for an unreachable relay — a resolver that throws, not returns */
const throwingResolver = async (): Promise<VerifiedIdentity | undefined> => {
  throw new Error('relay unreachable');
};

type Claimant = ReturnType<typeof makeIdentity>;

/**
 * Sign a claim JWS from an arbitrary payload, bypassing the signer's validation.
 * Used to probe what the VERIFIER accepts for payloads a conforming signer would
 * never mint.
 */
const signRaw = async (
  claimant: Claimant,
  payload: Record<string, unknown>,
  overrides: { typ?: string; cid?: string; kid?: string } = {},
) => {
  const encoded = await dagCborCanonicalEncode(payload);
  return createJws({
    header: {
      alg: 'EdDSA',
      typ: overrides.typ ?? 'did:dfos:credit-claim',
      kid: overrides.kid ?? claimant.kid,
      cid: overrides.cid ?? encoded.cid.toString(),
    },
    payload,
    sign: claimant.signer,
  });
};

const basePayload = (claimant: Claimant, contentId: string) => ({
  version: 1 as const,
  type: 'credit-claim' as const,
  contentId,
  did: claimant.did,
  role: 'author',
  createdAt: '2026-03-07T00:00:00.000Z',
});

/** Assert a rejection is a typed verify error carrying the expected verdict */
const expectVerdict = async (promise: Promise<unknown>, reason: 'invalid' | 'unverifiable') => {
  const error = await promise.then(
    () => {
      throw new Error('expected the verification to reject');
    },
    (thrown: unknown) => thrown,
  );
  expect(error).toBeInstanceOf(CreditClaimVerifyError);
  expect((error as CreditClaimVerifyError).reason).toBe(reason);
};

// =============================================================================
// credit claim
// =============================================================================

describe('credit claim', () => {
  it('should create and verify a credit claim', async () => {
    const claimant = makeIdentity();
    const contentId = makeContentId();

    const { jwsToken, claimCID } = await signCreditClaim({
      contentId,
      did: claimant.did,
      role: 'photography',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    expect(jwsToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(claimCID).toBeTruthy();

    const verified = await verifyCreditClaim(jwsToken, {
      resolveIdentity: resolverFor(claimant.identity),
    });

    expect(verified.did).toBe(claimant.did);
    expect(verified.contentId).toBe(contentId);
    expect(verified.role).toBe('photography');
    expect(verified.claimCID).toBe(claimCID);
    expect(verified.signerKeyId).toBe(claimant.kid);
    expect(verified.createdAt).toMatch(/\.000Z$/);
    expect(verified.asOfDocumentCID).toBeUndefined();
  });

  it('should derive the kid from did + keyId', async () => {
    // a kid↔did mismatch is unrepresentable at sign time
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    const header = JSON.parse(
      Buffer.from(jwsToken.split('.')[0]!, 'base64url').toString('utf-8'),
    ) as { kid: string };
    expect(header.kid).toBe(`${claimant.did}#${claimant.keyId}`);
  });

  it('should re-derive identical bytes from a createdAt override', async () => {
    const claimant = makeIdentity();
    const contentId = makeContentId();
    const createdAt = '2026-03-07T00:00:00.000Z';

    const first = await signCreditClaim({
      contentId,
      did: claimant.did,
      role: 'author',
      createdAt,
      signer: claimant.signer,
      keyId: claimant.keyId,
    });
    const second = await signCreditClaim({
      contentId,
      did: claimant.did,
      role: 'author',
      createdAt,
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    expect(first.jwsToken).toBe(second.jwsToken);
    expect(first.claimCID).toBe(second.claimCID);
  });

  it('should normalize a createdAt override to whole seconds', async () => {
    // `createdAt` is inside the signed payload, so it is part of the claim CID. An
    // override carrying real milliseconds through on one implementation but not the
    // other would fork claim identity, so BOTH signers truncate. The assertion
    // anchors on the existing cross-language parity CID: signing the parity
    // payload's fields with a `.777Z` override MUST land on the same claim CID as
    // the `.000Z` vector, which is what "the override is normalized" means. The Go
    // twin asserts the same literal from the same override
    // (TestCreditClaimCreatedAtOverrideIsNormalized).
    const claimant = makeIdentity();

    const { claimCID } = await signCreditClaim({
      contentId: 'cv7n8vkvr64cctf3294h9k4eanhff8z',
      did: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
      role: 'photography',
      createdAt: '2026-03-07T00:00:00.777Z',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    expect(claimCID).toBe('bafyreih4ge62ips6u6ek3y6sg2a6xlwuciz5njqftcxfoytfius4lekohq');
  });

  it('should reject an unparseable createdAt override', async () => {
    const claimant = makeIdentity();

    await expect(
      signCreditClaim({
        contentId: makeContentId(),
        did: claimant.did,
        role: 'author',
        createdAt: 'last thursday',
        signer: claimant.signer,
        keyId: claimant.keyId,
      }),
    ).rejects.toThrow('unparseable createdAt');
  });

  it('should round-trip the optional asOfDocumentCID flavor', async () => {
    const claimant = makeIdentity();
    const asOfDocumentCID = 'bafyrei' + 'a'.repeat(52);

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      asOfDocumentCID,
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    const verified = await verifyCreditClaim(jwsToken, {
      resolveIdentity: resolverFor(claimant.identity),
    });

    expect(verified.asOfDocumentCID).toBe(asOfDocumentCID);
  });

  it('should refuse to sign an empty asOfDocumentCID', async () => {
    // the empty-string shape is a DIFFERENT signed encoding from an absent field,
    // so minting it would produce a claim both verifiers reject
    const claimant = makeIdentity();

    await expect(
      signCreditClaim({
        contentId: makeContentId(),
        did: claimant.did,
        role: 'author',
        asOfDocumentCID: '',
        signer: claimant.signer,
        keyId: claimant.keyId,
      }),
    ).rejects.toThrow('asOfDocumentCID must be non-empty when present');
  });

  it('should reject a present-but-non-string asOfDocumentCID', async () => {
    // exactly what a nullable-optional producer emits (`?? null`, a nil *string,
    // Python None) — the Go twin must reject these identically
    const claimant = makeIdentity();

    for (const bad of [null, 42, '', true]) {
      const payload = { ...basePayload(claimant, makeContentId()), asOfDocumentCID: bad };
      const jwsToken = await signRaw(claimant, payload);

      await expectVerdict(
        verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
        'invalid',
      );
    }
  });

  it('should reject a claimant that is not a DID', async () => {
    const claimant = makeIdentity();
    const payload = { ...basePayload(claimant, makeContentId()), did: 'not-a-did' };
    // kid must agree with the payload did, or the kid check fires first
    const jwsToken = await signRaw(claimant, payload, { kid: `not-a-did#${claimant.keyId}` });

    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
      'invalid',
    );

    // and the signer refuses it too
    await expect(
      signCreditClaim({
        contentId: makeContentId(),
        did: 'not-a-did',
        role: 'author',
        signer: claimant.signer,
        keyId: claimant.keyId,
      }),
    ).rejects.toThrow('did must be a DID');
  });

  // ---------------------------------------------------------------------------
  // cross-language byte parity
  // ---------------------------------------------------------------------------

  it('should derive the cross-language parity CIDs for a fixed payload', async () => {
    // The Go twin (credit_claim_test.go, TestCreditClaimCIDParityVector) encodes
    // this same fixed payload and MUST derive these exact CIDs. A divergence means
    // the two implementations disagree on claim bytes, which forks claim identity —
    // so these literals are normative, not snapshots to re-bless when they break.
    const payload = {
      version: 1 as const,
      type: 'credit-claim' as const,
      contentId: 'cv7n8vkvr64cctf3294h9k4eanhff8z',
      did: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
      role: 'photography',
      createdAt: '2026-03-07T00:00:00.000Z',
    };
    const asOfDocumentCID = 'bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne';

    const bare = await dagCborCanonicalEncode(payload);
    expect(bare.cid.toString()).toBe('bafyreih4ge62ips6u6ek3y6sg2a6xlwuciz5njqftcxfoytfius4lekohq');

    const withAsOf = await dagCborCanonicalEncode({ ...payload, asOfDocumentCID });
    expect(withAsOf.cid.toString()).toBe(
      'bafyreihgzssoutaannyjdvnymcerl6pe5zhx5jeb576igp777so2qmdcri',
    );

    // the fixed payload is a legal claim, not just legal CBOR
    expect(CreditClaimPayload.safeParse(payload).success).toBe(true);
  });

  it('should reject a claim whose kid DID does not match the payload did', async () => {
    const claimant = makeIdentity();
    const other = makeIdentity();

    // signed under `other`'s kid while naming `claimant` in the payload — the
    // "someone else claims your credit for you" shape. The signer can no longer
    // produce this, so it must be forged directly.
    const jwsToken = await signRaw(other, basePayload(claimant, makeContentId()));

    await expectVerdict(
      verifyCreditClaim(jwsToken, {
        resolveIdentity: resolverFor(claimant.identity, other.identity),
      }),
      'invalid',
    );
  });

  it('should reject a claim whose signature does not match the resolved key', async () => {
    const claimant = makeIdentity();
    const impostor = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    // same DID, same key id, different key bytes — isolates the signature check
    // from key lookup
    const swapped: VerifiedIdentity = {
      ...claimant.identity,
      assertKeys: [multikey(claimant.keyId, impostor.keypair.publicKey)],
    };

    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(swapped) }),
      'invalid',
    );
  });

  it('should reject a claim with the wrong typ', async () => {
    const claimant = makeIdentity();
    const jwsToken = await signRaw(claimant, basePayload(claimant, makeContentId()), {
      typ: 'did:dfos:revocation',
    });

    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
      'invalid',
    );
  });

  it('should reject a claim whose header cid does not commit to the payload', async () => {
    const claimant = makeIdentity();
    const payload = basePayload(claimant, makeContentId());
    // a CID for a DIFFERENT payload — the signature is valid over these exact
    // bytes, so only CID re-derivation catches it
    const decoy = await dagCborCanonicalEncode({ ...payload, role: 'editor' });
    const jwsToken = await signRaw(claimant, payload, { cid: decoy.cid.toString() });

    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
      'invalid',
    );
  });

  it('should refuse to sign a claim over the size cap', async () => {
    // a signer must not mint a token every verifier — including its own — rejects
    const claimant = makeIdentity();

    await expect(
      signCreditClaim({
        contentId: makeContentId(),
        did: claimant.did,
        role: 'x'.repeat(MAX_CREDIT_CLAIM_SIZE + 1),
        signer: claimant.signer,
        keyId: claimant.keyId,
      }),
    ).rejects.toThrow('credit claim exceeds max size');
  });

  it('should reject a claim exceeding the size cap on verify', async () => {
    const claimant = makeIdentity();
    const payload = {
      ...basePayload(claimant, makeContentId()),
      role: 'x'.repeat(MAX_CREDIT_CLAIM_SIZE + 1),
    };
    const jwsToken = await signRaw(claimant, payload);

    expect(jwsToken.length).toBeGreaterThan(MAX_CREDIT_CLAIM_SIZE);
    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
      'invalid',
    );
  });

  it('should reject malformed JWS', async () => {
    const claimant = makeIdentity();

    await expectVerdict(
      verifyCreditClaim('not-a-jws', { resolveIdentity: resolverFor(claimant.identity) }),
      'invalid',
    );
  });

  it('should reject a decodable JWS with a malformed header as invalid', async () => {
    // The protected header is JSON.parsed and CAST, so `kid` can be absent or a
    // non-string on a token that decodes perfectly well. Reading it unguarded threw
    // a raw TypeError, which the entry classifier then reported as `unverifiable` —
    // "could not check" for a claim we did check and found malformed.
    const claimant = makeIdentity();
    const payload = basePayload(claimant, makeContentId());
    const cid = (await dagCborCanonicalEncode(payload)).cid.toString();

    const headers: Record<string, unknown>[] = [
      { alg: 'EdDSA', typ: 'did:dfos:credit-claim', cid }, // kid absent
      { alg: 'EdDSA', typ: 'did:dfos:credit-claim', kid: 42, cid },
      { alg: 'EdDSA', typ: 'did:dfos:credit-claim', kid: null, cid },
      { alg: 'EdDSA', kid: claimant.kid, cid }, // typ absent
      { alg: 'EdDSA', typ: 7, kid: claimant.kid, cid },
    ];

    const b64 = (value: unknown) =>
      Buffer.from(JSON.stringify(value), 'utf-8').toString('base64url');

    for (const header of headers) {
      const signingInput = `${b64(header)}.${b64(payload)}`;
      const signature = Buffer.from(
        await claimant.signer(new TextEncoder().encode(signingInput)),
      ).toString('base64url');
      const jwsToken = `${signingInput}.${signature}`;

      // three parts and valid base64url — the failure is the header SHAPE, not the
      // encoding, so this is not the malformed-JWS path above
      expect(jwsToken.split('.')).toHaveLength(3);
      await expectVerdict(
        verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
        'invalid',
      );
    }
  });

  it('should refuse to sign a claim bound to a non-contentId', async () => {
    const claimant = makeIdentity();

    // an artifact CID is immutable and chainless — it can never host a credits
    // slot, so it is not a legal binder
    await expect(
      signCreditClaim({
        contentId: 'bafyrei' + 'a'.repeat(52),
        did: claimant.did,
        role: 'author',
        signer: claimant.signer,
        keyId: claimant.keyId,
      }),
    ).rejects.toThrow('contentId must be a 31-char content chain id');
  });

  // ---------------------------------------------------------------------------
  // the invalid / unverifiable split
  // ---------------------------------------------------------------------------

  it('should report an unresolvable claimant as unverifiable, not invalid', async () => {
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor() }),
      'unverifiable',
    );
  });

  it('should report a THROWING resolver as unverifiable, not invalid', async () => {
    // a relay outage is "could not check", never "checked and failed" — the
    // distinction the spec says a consumer MUST keep
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: throwingResolver }),
      'unverifiable',
    );
  });

  it('should report a resolved identity missing the signing key as invalid', async () => {
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    const keyless: VerifiedIdentity = { ...claimant.identity, assertKeys: [] };
    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(keyless) }),
      'invalid',
    );
  });

  // ---------------------------------------------------------------------------
  // contentId binding (anti-replay)
  // ---------------------------------------------------------------------------

  it('should accept a claim whose contentId matches expectedContentId', async () => {
    const claimant = makeIdentity();
    const contentId = makeContentId();

    const { jwsToken } = await signCreditClaim({
      contentId,
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    const verified = await verifyCreditClaim(jwsToken, {
      resolveIdentity: resolverFor(claimant.identity),
      expectedContentId: contentId,
    });

    expect(verified.contentId).toBe(contentId);
  });

  it('should reject a claim replayed into another chain document', async () => {
    const claimant = makeIdentity();
    const otherChain = makeContentId();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    await expectVerdict(
      verifyCreditClaim(jwsToken, {
        resolveIdentity: resolverFor(claimant.identity),
        expectedContentId: otherChain,
      }),
      'invalid',
    );
  });

  it('should reject an EMPTY expectedContentId rather than skipping the binder', async () => {
    // the empty string is a zero value (unhydrated field, failed parse), never a
    // request for unbound semantics — the Go twin errors on the same input
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    await expect(
      verifyCreditClaim(jwsToken, {
        resolveIdentity: resolverFor(claimant.identity),
        expectedContentId: '',
      }),
    ).rejects.toThrow('expectedContentId must be a non-empty contentId');
  });

  // ---------------------------------------------------------------------------
  // doctrine
  // ---------------------------------------------------------------------------

  it('should still verify a claim whose claimant identity is deleted', async () => {
    // DELIBERATE: attribution is historical fact and survives a claimant
    // tombstone. Credentials take the opposite rule (a deleted issuer's
    // credentials die) because authority must die with the identity holding it.
    // If this test ever "fails", verifyCreditClaim grew an isDeleted gate it
    // must not have.
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    const tombstoned: VerifiedIdentity = { ...claimant.identity, isDeleted: true };

    const verified = await verifyCreditClaim(jwsToken, {
      resolveIdentity: resolverFor(tombstoned),
    });

    expect(verified.did).toBe(claimant.did);
    expect(verified.role).toBe('author');
  });

  it('should verify a claim signed before a key rotation, given a historical resolver', async () => {
    // Key history is the RESOLVER's contract. A resolver that merges every key the
    // identity chain has ever held — as dfos-client's does, so credential validity
    // persists across rotations — keeps old credits verifying. A current-state-only
    // resolver reports `invalid` for this exact claim and silently un-credits real
    // work, which is why the contract is documented on the verifier.
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'photography',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    // the claimant rotates: a new key replaces the old one in CURRENT state
    const rotated = createNewEd25519Keypair();
    const rotatedKeyId = generateId('key');
    const currentStateOnly: VerifiedIdentity = {
      ...claimant.identity,
      assertKeys: [multikey(rotatedKeyId, rotated.publicKey)],
    };
    const historical: VerifiedIdentity = {
      ...claimant.identity,
      assertKeys: [
        multikey(rotatedKeyId, rotated.publicKey),
        multikey(claimant.keyId, claimant.keypair.publicKey),
      ],
    };

    // current-state-only: the signing key is gone, so the claim reads as invalid
    await expectVerdict(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(currentStateOnly) }),
      'invalid',
    );

    // historical (the required contract): the claim still verifies
    const verified = await verifyCreditClaim(jwsToken, {
      resolveIdentity: resolverFor(historical),
    });
    expect(verified.role).toBe('photography');
  });
});

// =============================================================================
// credit entry — the full three-component bind
// =============================================================================

describe('credit entry', () => {
  const claimedEntry = async () => {
    const claimant = makeIdentity();
    const contentId = makeContentId();
    const { jwsToken } = await signCreditClaim({
      contentId,
      did: claimant.did,
      role: 'photography',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });
    return { claimant, contentId, jwsToken };
  };

  it('should resolve a bound entry as claimed', async () => {
    const { claimant, contentId, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'photography', name: 'Alice', claim: jwsToken },
      { resolveIdentity: resolverFor(claimant.identity), contentId },
    );

    expect(result.state).toBe('claimed');
    expect(result.claim?.role).toBe('photography');
  });

  it('should resolve an entry with no claim as unclaimed', async () => {
    const claimant = makeIdentity();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'author' },
      { resolveIdentity: resolverFor(claimant.identity), contentId: makeContentId() },
    );

    expect(result.state).toBe('unclaimed');
    expect(result.claim).toBeUndefined();
  });

  it('should resolve a role mismatch as invalid', async () => {
    const { claimant, contentId, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'editor', claim: jwsToken },
      { resolveIdentity: resolverFor(claimant.identity), contentId },
    );

    expect(result.state).toBe('invalid');
    expect(result.claim).toBeUndefined();
  });

  it('should resolve a claim-bearing entry with no role as invalid', async () => {
    // an absent entry role is a BIND MISMATCH, not a wildcard, and never unclaimed
    const { claimant, contentId, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: claimant.did, claim: jwsToken },
      { resolveIdentity: resolverFor(claimant.identity), contentId },
    );

    expect(result.state).toBe('invalid');
  });

  it('should resolve a did mismatch as invalid', async () => {
    const { claimant, contentId, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: 'did:dfos:someone-else', role: 'photography', claim: jwsToken },
      { resolveIdentity: resolverFor(claimant.identity), contentId },
    );

    expect(result.state).toBe('invalid');
  });

  it('should resolve a claim replayed from another chain as invalid', async () => {
    const { claimant, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'photography', claim: jwsToken },
      { resolveIdentity: resolverFor(claimant.identity), contentId: makeContentId() },
    );

    expect(result.state).toBe('invalid');
  });

  it('should resolve a non-string claim as invalid', async () => {
    const claimant = makeIdentity();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'photography', claim: 42 },
      { resolveIdentity: resolverFor(claimant.identity), contentId: makeContentId() },
    );

    expect(result.state).toBe('invalid');
  });

  it('should resolve an unresolvable claimant as unverifiable', async () => {
    const { claimant, contentId, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'photography', claim: jwsToken },
      { resolveIdentity: resolverFor(), contentId },
    );

    expect(result.state).toBe('unverifiable');
  });

  it('should resolve a relay outage as unverifiable', async () => {
    const { claimant, contentId, jwsToken } = await claimedEntry();

    const result = await verifyCreditEntry(
      { did: claimant.did, role: 'photography', claim: jwsToken },
      { resolveIdentity: throwingResolver, contentId },
    );

    expect(result.state).toBe('unverifiable');
  });

  it('should require the hosting contentId', async () => {
    const claimant = makeIdentity();

    await expect(
      verifyCreditEntry(
        { did: claimant.did, role: 'author' },
        { resolveIdentity: resolverFor(claimant.identity), contentId: '' },
      ),
    ).rejects.toThrow('requires the hosting chain contentId');
  });
});
