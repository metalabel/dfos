import { describe, expect, it } from 'vitest';
import { signRevocation, verifyRevocation } from '../src/chain';
import { createNewEd25519Keypair, generateId, signPayloadEd25519 } from '../src/crypto';

// =============================================================================
// helpers
// =============================================================================

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, did, kid, signer };
};

const resolveKey = (identities: Map<string, { keypair: { publicKey: Uint8Array } }>) => {
  return async (kid: string) => {
    const hashIdx = kid.indexOf('#');
    const did = kid.substring(0, hashIdx);
    const id = identities.get(did);
    if (!id) throw new Error(`unknown DID: ${did}`);
    return id.keypair.publicKey;
  };
};

// =============================================================================
// revocation
// =============================================================================

describe('revocation', () => {
  it('should create and verify a revocation', async () => {
    const issuer = makeIdentity();
    const credentialCID = 'bafyrei' + 'a'.repeat(52);

    const { jwsToken, revocationCID } = await signRevocation({
      issuerDID: issuer.did,
      credentialCID,
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    expect(jwsToken).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(revocationCID).toBeTruthy();

    const identities = new Map([[issuer.did, issuer]]);
    const verified = await verifyRevocation({
      jwsToken,
      resolveKey: resolveKey(identities),
    });

    expect(verified.did).toBe(issuer.did);
    expect(verified.credentialCID).toBe(credentialCID);
    expect(verified.revocationCID).toBe(revocationCID);
    expect(verified.signerKeyId).toBe(issuer.kid);
    expect(verified.createdAt).toBeTruthy();
  });

  it('should reject revocation signed by wrong DID', async () => {
    const issuer = makeIdentity();
    const wrongSigner = makeIdentity();
    const credentialCID = 'bafyrei' + 'b'.repeat(52);

    const { jwsToken } = await signRevocation({
      issuerDID: issuer.did,
      credentialCID,
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    // resolve to wrong identity's key → signature will fail
    const identities = new Map([[issuer.did, wrongSigner]]);
    await expect(
      verifyRevocation({ jwsToken, resolveKey: resolveKey(identities) }),
    ).rejects.toThrow('invalid revocation signature');
  });

  it('should reject revocation with tampered payload', async () => {
    const issuer = makeIdentity();
    const credentialCID = 'bafyrei' + 'c'.repeat(52);

    const { jwsToken } = await signRevocation({
      issuerDID: issuer.did,
      credentialCID,
      signer: issuer.signer,
      keyId: issuer.keyId,
    });

    // tamper with the payload by replacing the credentialCID
    const parts = jwsToken.split('.');
    const payloadBytes = new TextEncoder().encode(
      JSON.stringify({
        type: 'revocation',
        did: issuer.did,
        credentialCID: 'bafyrei' + 'd'.repeat(52),
        createdAt: new Date().toISOString().replace(/\d{3}Z$/, '000Z'),
      }),
    );
    const tamperedB64 = btoa(String.fromCharCode(...payloadBytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const tamperedToken = `${parts[0]}.${tamperedB64}.${parts[2]}`;

    const identities = new Map([[issuer.did, issuer]]);
    await expect(
      verifyRevocation({ jwsToken: tamperedToken, resolveKey: resolveKey(identities) }),
    ).rejects.toThrow();
  });

  it('should reject malformed JWS', async () => {
    const issuer = makeIdentity();
    const identities = new Map([[issuer.did, issuer]]);

    await expect(
      verifyRevocation({ jwsToken: 'not-a-jws', resolveKey: resolveKey(identities) }),
    ).rejects.toThrow('failed to decode revocation JWS');
  });

  it('should reject revocation with wrong typ', async () => {
    const issuer = makeIdentity();
    const identities = new Map([[issuer.did, issuer]]);

    // manually create a JWS with wrong typ
    const { createJws, dagCborCanonicalEncode } = await import('../src/crypto');
    const payload = {
      version: 1 as const,
      type: 'revocation' as const,
      did: issuer.did,
      credentialCID: 'bafyrei' + 'e'.repeat(52),
      createdAt: new Date().toISOString().replace(/\d{3}Z$/, '000Z'),
    };
    const encoded = await dagCborCanonicalEncode(payload);
    const jwsToken = await createJws({
      header: {
        alg: 'EdDSA',
        typ: 'did:dfos:beacon',
        kid: issuer.kid,
        cid: encoded.cid.toString(),
      },
      payload: payload as unknown as Record<string, unknown>,
      sign: issuer.signer,
    });

    await expect(
      verifyRevocation({ jwsToken, resolveKey: resolveKey(identities) }),
    ).rejects.toThrow('invalid revocation typ');
  });
});
