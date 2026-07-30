import { describe, expect, it } from 'vitest';
import {
  CreditClaimPayload,
  encodeEd25519Multikey,
  MAX_CREDIT_CLAIM_SIZE,
  signCreditClaim,
  verifyCreditClaim,
} from '../src/chain';
import type { VerifiedIdentity } from '../src/chain';
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

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    assertKeys: [
      { id: keyId, type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey) },
    ],
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
    const contentId = makeContentId();

    // hand-build a claim signed under `other`'s kid while naming `claimant` in
    // the payload — the "someone else claims your credit for you" shape
    const payload = {
      version: 1 as const,
      type: 'credit-claim' as const,
      contentId,
      did: claimant.did,
      role: 'author',
      createdAt: new Date().toISOString().replace(/\d{3}Z$/, '000Z'),
    };
    const encoded = await dagCborCanonicalEncode(payload);
    const jwsToken = await createJws({
      header: {
        alg: 'EdDSA',
        typ: 'did:dfos:credit-claim',
        kid: other.kid,
        cid: encoded.cid.toString(),
      },
      payload: payload as unknown as Record<string, unknown>,
      sign: other.signer,
    });

    await expect(
      verifyCreditClaim(jwsToken, {
        resolveIdentity: resolverFor(claimant.identity, other.identity),
      }),
    ).rejects.toThrow('credit claim kid DID does not match payload did');
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
      assertKeys: [
        {
          id: claimant.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(impostor.keypair.publicKey),
        },
      ],
    };

    await expect(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(swapped) }),
    ).rejects.toThrow('invalid credit claim signature');
  });

  it('should reject a claim with the wrong typ', async () => {
    const claimant = makeIdentity();

    const payload = {
      version: 1 as const,
      type: 'credit-claim' as const,
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      createdAt: new Date().toISOString().replace(/\d{3}Z$/, '000Z'),
    };
    const encoded = await dagCborCanonicalEncode(payload);
    const jwsToken = await createJws({
      header: {
        alg: 'EdDSA',
        typ: 'did:dfos:revocation',
        kid: claimant.kid,
        cid: encoded.cid.toString(),
      },
      payload: payload as unknown as Record<string, unknown>,
      sign: claimant.signer,
    });

    await expect(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
    ).rejects.toThrow('invalid credit claim typ');
  });

  it('should reject a claim whose header cid does not commit to the payload', async () => {
    const claimant = makeIdentity();

    const payload = {
      version: 1 as const,
      type: 'credit-claim' as const,
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      createdAt: new Date().toISOString().replace(/\d{3}Z$/, '000Z'),
    };
    // sign a header carrying a CID for a DIFFERENT payload — the signature is
    // valid over these exact bytes, so only CID re-derivation catches it
    const decoy = await dagCborCanonicalEncode({ ...payload, role: 'editor' });
    const jwsToken = await createJws({
      header: {
        alg: 'EdDSA',
        typ: 'did:dfos:credit-claim',
        kid: claimant.kid,
        cid: decoy.cid.toString(),
      },
      payload: payload as unknown as Record<string, unknown>,
      sign: claimant.signer,
    });

    await expect(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
    ).rejects.toThrow('credit claim cid mismatch');
  });

  it('should reject a claim exceeding the size cap', async () => {
    const claimant = makeIdentity();

    // `role` carries no separate length cap — the aggregate token cap is the
    // single byte arbiter, so an oversized role is what trips it
    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'x'.repeat(MAX_CREDIT_CLAIM_SIZE + 1),
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    expect(jwsToken.length).toBeGreaterThan(MAX_CREDIT_CLAIM_SIZE);
    await expect(
      verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor(claimant.identity) }),
    ).rejects.toThrow('credit claim exceeds max size');
  });

  it('should reject malformed JWS', async () => {
    const claimant = makeIdentity();

    await expect(
      verifyCreditClaim('not-a-jws', { resolveIdentity: resolverFor(claimant.identity) }),
    ).rejects.toThrow('failed to decode credit claim JWS');
  });

  it('should reject a claim naming an unresolvable claimant', async () => {
    const claimant = makeIdentity();

    const { jwsToken } = await signCreditClaim({
      contentId: makeContentId(),
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    await expect(verifyCreditClaim(jwsToken, { resolveIdentity: resolverFor() })).rejects.toThrow(
      'claimant identity not found',
    );
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

    await expect(
      verifyCreditClaim(jwsToken, {
        resolveIdentity: resolverFor(claimant.identity),
        expectedContentId: otherChain,
      }),
    ).rejects.toThrow('does not match expected');
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
});
