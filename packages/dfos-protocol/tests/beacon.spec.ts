import { describe, expect, it } from 'vitest';
import { encodeEd25519Multikey, signBeacon, verifyBeacon } from '../src/chain';
import type { BeaconPayload } from '../src/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

// =============================================================================
// beacon
// =============================================================================

describe('beacon', () => {
  const makeIdentity = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const did = `did:dfos:${generateId('test').substring(5)}`;
    const kid = `${did}#${keyId}`;
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    const resolveKey = async (_kid: string) => keypair.publicKey;
    return { keypair, keyId, did, kid, signer, resolveKey };
  };

  const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

  const manifestContentId = 'manifest_' + generateId('test').substring(5);

  // --- round-trip ---

  it('should sign and verify a beacon round-trip', async () => {
    const id = makeIdentity();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: ts(),
    };

    const { jwsToken, beaconCID } = await signBeacon({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyBeacon({
      jwsToken,
      resolveKey: id.resolveKey,
    });

    expect(result.did).toBe(id.did);
    expect(result.manifestContentId).toBe(manifestContentId);
    expect(result.beaconCID).toBe(beaconCID);
  });

  // --- CID determinism ---

  it('should produce deterministic CID for same payload', async () => {
    const id = makeIdentity();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: '2026-01-01T00:00:00.000Z',
    };

    const r1 = await signBeacon({ payload, signer: id.signer, kid: id.kid });
    const r2 = await signBeacon({ payload, signer: id.signer, kid: id.kid });

    expect(r1.beaconCID).toBe(r2.beaconCID);
  });

  // --- JWS header format ---

  it('should use did:dfos:beacon as JWS typ with correct kid and cid', async () => {
    const id = makeIdentity();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: ts(),
    };

    const { jwsToken, beaconCID } = await signBeacon({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    const decoded = decodeJwsUnsafe(jwsToken)!;
    expect(decoded.header.typ).toBe('did:dfos:beacon');
    expect(decoded.header.kid).toBe(id.kid);
    expect(decoded.header.alg).toBe('EdDSA');
    expect(decoded.header.cid).toBe(beaconCID);
  });

  // --- kid DID mismatch ---

  it('should reject beacon with kid DID not matching payload did', async () => {
    const author = makeIdentity();
    const other = makeIdentity();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: author.did,
      manifestContentId,
      createdAt: ts(),
    };

    // sign with other's kid (DID does not match payload.did)
    const { jwsToken } = await signBeacon({
      payload,
      signer: other.signer,
      kid: other.kid,
    });

    await expect(verifyBeacon({ jwsToken, resolveKey: other.resolveKey })).rejects.toThrow(
      /kid DID does not match/i,
    );
  });

  // --- clock skew: too far in the future ---

  it('should reject beacon with createdAt more than 5 minutes in the future', async () => {
    const id = makeIdentity();
    const now = Date.now();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: new Date(now + 10 * 60_000).toISOString(), // 10 min ahead
    };

    const { jwsToken } = await signBeacon({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    await expect(verifyBeacon({ jwsToken, resolveKey: id.resolveKey, now })).rejects.toThrow(
      /too far in the future/i,
    );
  });

  // --- clock skew: within tolerance ---

  it('should accept beacon with createdAt within 5 minutes of now', async () => {
    const id = makeIdentity();
    const now = Date.now();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: new Date(now + 4 * 60_000).toISOString(), // 4 min ahead — within 5 min tolerance
    };

    const { jwsToken } = await signBeacon({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyBeacon({ jwsToken, resolveKey: id.resolveKey, now });
    expect(result.manifestContentId).toBe(manifestContentId);
  });

  // --- invalid signature ---

  it('should reject beacon with invalid signature (wrong key)', async () => {
    const id = makeIdentity();
    const wrongKey = createNewEd25519Keypair();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: ts(),
    };

    const { jwsToken } = await signBeacon({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    // resolve to wrong key
    await expect(
      verifyBeacon({
        jwsToken,
        resolveKey: async () => wrongKey.publicKey,
      }),
    ).rejects.toThrow(/invalid beacon signature/i);
  });

  // --- tampered payload ---

  it('should reject beacon with tampered payload (cid mismatch)', async () => {
    const id = makeIdentity();

    const payload: BeaconPayload = {
      type: 'beacon',
      did: id.did,
      manifestContentId,
      createdAt: ts(),
    };

    const { jwsToken } = await signBeacon({
      payload,
      signer: id.signer,
      kid: id.kid,
    });

    // tamper with the payload portion of the JWS (replace manifestContentId)
    const decoded = decodeJwsUnsafe(jwsToken)!;
    const tampered: BeaconPayload = {
      ...(decoded.payload as unknown as BeaconPayload),
      manifestContentId: 'tampered_content_id',
    };
    const tamperedPayloadB64 = btoa(JSON.stringify(tampered))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const parts = jwsToken.split('.');
    const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

    await expect(
      verifyBeacon({ jwsToken: tamperedToken, resolveKey: id.resolveKey }),
    ).rejects.toThrow();
  });
});
