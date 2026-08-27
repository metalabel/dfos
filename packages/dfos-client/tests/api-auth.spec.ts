/*

  API-AUTH — byte contract + request-proof verification

  The load-bearing piece is `apiRequestSigningInput`: the PURE bytes both halves
  share. Every literal in the vector block below is pinned byte-identically in
  packages/dfos-protocol-go/api_auth_test.go — if one side moves, both suites go
  red rather than the two signers silently forking.

  The credential-chain vectors (steps 8–11) are TS-only, matching the boundary
  the Go twin draws; the byte-contract vectors live in both.

*/

import { createDFOSCredential, type Attenuation } from '@metalabel/dfos-protocol/credentials';
import {
  base64urlDecode,
  base64urlEncode,
  importEd25519Keypair,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import {
  apiIdentitySigningInput,
  apiRequestSigningInput,
  ApiRequestVerifyError,
  buildApiAuthHeaders,
  buildApiIdentityHeaders,
  createApiAuthFetch,
  DEFAULT_API_ACTION,
  EMPTY_BODY_SHA256,
  IDENTITY_PROOF_JWS_TYP,
  MAX_REQUEST_PROOF_SIZE,
  REQUEST_PROOF_JWS_TYP,
  sha256BodyHash,
  signApiIdentityRequest,
  signApiRequest,
  verifyApiIdentityRequest,
  verifyApiRequest,
  type IdentityProofPayload,
  type RequestProofPayload,
} from '../src/api-auth';
import { createClient } from '../src/client';
import type { RevChecker } from '../src/types';
import { buildIdentity, cidOf, fakePeerClient, makeKey } from './fixtures';

const RELAY = 'https://relay.test';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// -----------------------------------------------------------------------------
// the cross-language vector set — MUST match api_auth_test.go byte for byte
// -----------------------------------------------------------------------------

const VECTOR_CID = 'bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne';
const VECTOR_KID = 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#key_api_auth_vector';
const VECTOR_IAT = 1772841600;

const VECTOR_CANONICAL =
  '{"method":"GET","host":"api.dfos.com","path":"/v0/profile","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","credentialCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","iat":1772841600}';
const VECTOR_CANONICAL_QUERY =
  '{"method":"GET","host":"api.dfos.com","path":"/v0/profile?a=1&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","credentialCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","iat":1772841600}';
const VECTOR_CANONICAL_HTML =
  '{"method":"GET","host":"api.dfos.com","path":"/v0/profile?q=<a>&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","credentialCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","iat":1772841600}';
const VECTOR_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlcXVlc3QtcHJvb2YiLCJraWQiOiJkaWQ6ZGZvczpuemtmODM4ZWZyNDI0NDMzcm4ycnprZHY4aDd0OWFlI2tleV9hcGlfYXV0aF92ZWN0b3IifQ.eyJtZXRob2QiOiJHRVQiLCJob3N0IjoiYXBpLmRmb3MuY29tIiwicGF0aCI6Ii92MC9wcm9maWxlIiwiYm9keUhhc2giOiI0N0RFUXBqOEhCU2EtX1RJbVctNUpDZXVRZVJrbTVOTXBKV1pHM2hTdUZVIiwiY3JlZGVudGlhbENJRCI6ImJhZnlyZWljb2dodmp6bnZsaXVsb3h4bWJmNTR0cHpxd2FobnFwaWxrN25jeGVwamluZWRwa2dhM25lIiwiaWF0IjoxNzcyODQxNjAwfQ.K2TZ7NC4ad9VRF2GM0J3YTNBl3DGdFMmYA6rqgJFGKXjd5WDU5zlqHZzhnWZO1tuplfq8tOeQ75upK_kGxQ2BA';

// The identity proof's half of the SAME fixture: the same seed, kid, iat, host,
// and paths, with credentialCID absent. Five members, canonical order
// method, host, path, bodyHash, iat.
const VECTOR_IDENTITY_CANONICAL =
  '{"method":"GET","host":"api.dfos.com","path":"/v0/profile","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","iat":1772841600}';
const VECTOR_IDENTITY_CANONICAL_QUERY =
  '{"method":"GET","host":"api.dfos.com","path":"/v0/profile?a=1&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","iat":1772841600}';
const VECTOR_IDENTITY_CANONICAL_HTML =
  '{"method":"GET","host":"api.dfos.com","path":"/v0/profile?q=<a>&b=2","bodyHash":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","iat":1772841600}';
const VECTOR_IDENTITY_JWS =
  'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LXByb29mIiwia2lkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6a2R2OGg3dDlhZSNrZXlfYXBpX2F1dGhfdmVjdG9yIn0.eyJtZXRob2QiOiJHRVQiLCJob3N0IjoiYXBpLmRmb3MuY29tIiwicGF0aCI6Ii92MC9wcm9maWxlIiwiYm9keUhhc2giOiI0N0RFUXBqOEhCU2EtX1RJbVctNUpDZXVRZVJrbTVOTXBKV1pHM2hTdUZVIiwiaWF0IjoxNzcyODQxNjAwfQ.rfajvn-hrPlzQex_UwiMNzO5D5k0PR_TaGxxpl_t4PBUTeoZKGL9CLUX6TtPKyRm8D_JYP0wpQH8EGZORpMkCw';

/** The digest of `{"a":1}` — the body-bearing vector, pinned in both languages. */
const VECTOR_BODY_HASH = 'AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI';

const vectorPayload = (path: string): RequestProofPayload => ({
  method: 'GET',
  host: 'api.dfos.com',
  path,
  bodyHash: EMPTY_BODY_SHA256,
  credentialCID: VECTOR_CID,
  iat: VECTOR_IAT,
});

const vectorIdentityPayload = (path: string): IdentityProofPayload => ({
  method: 'GET',
  host: 'api.dfos.com',
  path,
  bodyHash: EMPTY_BODY_SHA256,
  iat: VECTOR_IAT,
});

/** The same fixed seed the Go vector test uses: bytes 0..31. */
const vectorSigner = (): ((message: Uint8Array) => Promise<Uint8Array>) => {
  const keypair = importEd25519Keypair(Uint8Array.from({ length: 32 }, (_, index) => index));
  return async (message) => signPayloadEd25519(message, keypair.privateKey);
};

describe('api-auth byte contract', () => {
  it('pins the shared canonical signing input, including the query-bearing paths', () => {
    expect(decoder.decode(apiRequestSigningInput(vectorPayload('/v0/profile')))).toBe(
      VECTOR_CANONICAL,
    );
    expect(decoder.decode(apiRequestSigningInput(vectorPayload('/v0/profile?a=1&b=2')))).toBe(
      VECTOR_CANONICAL_QUERY,
    );
    expect(decoder.decode(apiRequestSigningInput(vectorPayload('/v0/profile?q=<a>&b=2')))).toBe(
      VECTOR_CANONICAL_HTML,
    );
  });

  it('emits &, < and > LITERALLY — the vector that catches an encoding/json fork', () => {
    const canonical = decoder.decode(
      apiRequestSigningInput(vectorPayload('/v0/profile?q=<a>&b=2')),
    );
    expect(canonical).toContain('"path":"/v0/profile?q=<a>&b=2"');
    for (const escape of ['\\u0026', '\\u003c', '\\u003e']) {
      expect(canonical).not.toContain(escape);
    }
  });

  it('is order-independent across object construction', () => {
    const a = vectorPayload('/v0/profile');
    const b: RequestProofPayload = {
      iat: a.iat,
      credentialCID: a.credentialCID,
      bodyHash: a.bodyHash,
      path: a.path,
      host: a.host,
      method: a.method,
    };
    expect(apiRequestSigningInput(b)).toEqual(apiRequestSigningInput(a));
  });

  it('pins the signed request-proof vector, and the payload segment IS the signing input', async () => {
    const { proof } = await signApiRequest({
      method: 'GET',
      host: 'api.dfos.com',
      path: '/v0/profile',
      credentialCID: VECTOR_CID,
      kid: VECTOR_KID,
      sign: vectorSigner(),
      iat: VECTOR_IAT,
    });
    expect(proof).toBe(VECTOR_JWS);

    // `createJws` serializes JSON.stringify(payload), so the emitted payload
    // segment is `apiRequestSigningInput` by construction. That equivalence is the
    // whole reason there is one byte contract and not two — pin it, do not assume it.
    expect(proof.split('.')[1]).toBe(
      base64urlEncode(apiRequestSigningInput(vectorPayload('/v0/profile'))),
    );
  });

  it('pins the empty-body digest constant and a body-bearing digest', () => {
    expect(sha256BodyHash(new Uint8Array(0))).toBe(EMPTY_BODY_SHA256);
    expect(EMPTY_BODY_SHA256).toBe('47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU');
    expect(sha256BodyHash(encoder.encode('{"a":1}'))).toBe(VECTOR_BODY_HASH);
  });

  it('rejects every schema violation', () => {
    const base = vectorPayload('/v0/profile');
    const vectors: Array<[string, RequestProofPayload]> = [
      ['lowercase method', { ...base, method: 'get' }],
      ['mixed-case method', { ...base, method: 'GeT' }],
      ['empty method', { ...base, method: '' }],
      ['uppercase host', { ...base, host: 'API.dfos.com' }],
      ['host with scheme', { ...base, host: 'https://api.dfos.com' }],
      ['relative path', { ...base, path: 'v0/profile' }],
      ['path with fragment', { ...base, path: '/v0/profile#top' }],
      ['path with a space', { ...base, path: '/v0/pro file' }],
      ['padded bodyHash', { ...base, bodyHash: `${EMPTY_BODY_SHA256}=` }],
      ['short bodyHash', { ...base, bodyHash: EMPTY_BODY_SHA256.slice(0, 42) }],
      [
        'standard-base64 bodyHash',
        { ...base, bodyHash: EMPTY_BODY_SHA256.replace(/-/g, '+').replace(/_/g, '/') },
      ],
      ['empty credentialCID', { ...base, credentialCID: '' }],
      ['zero iat', { ...base, iat: 0 }],
      ['negative iat', { ...base, iat: -1 }],
      ['fractional iat', { ...base, iat: 1772841600.5 }],
    ];
    for (const [name, payload] of vectors) {
      expect(() => apiRequestSigningInput(payload), name).toThrow();
    }
  });

  it('rejects a NON-CANONICAL spelling of the right 32 bytes', () => {
    // `…SuFU` and `…SuFV` decode to the same 32 digest bytes (the trailing bits
    // differ); only the first re-encodes to itself. A verifier that decoded and
    // compared bytes would silently accept the second — this one MUST NOT.
    const nonCanonical = `${EMPTY_BODY_SHA256.slice(0, -1)}V`;
    expect(nonCanonical).not.toBe(EMPTY_BODY_SHA256);
    expect(() =>
      apiRequestSigningInput({ ...vectorPayload('/v0/profile'), bodyHash: nonCanonical }),
    ).toThrow(/canonical/);
  });
});

describe('api-auth identity byte contract', () => {
  it('pins the shared canonical signing input, including the query-bearing paths', () => {
    expect(decoder.decode(apiIdentitySigningInput(vectorIdentityPayload('/v0/profile')))).toBe(
      VECTOR_IDENTITY_CANONICAL,
    );
    expect(
      decoder.decode(apiIdentitySigningInput(vectorIdentityPayload('/v0/profile?a=1&b=2'))),
    ).toBe(VECTOR_IDENTITY_CANONICAL_QUERY);
    expect(
      decoder.decode(apiIdentitySigningInput(vectorIdentityPayload('/v0/profile?q=<a>&b=2'))),
    ).toBe(VECTOR_IDENTITY_CANONICAL_HTML);
  });

  it('is the request proof’s bytes MINUS credentialCID, and nothing else', () => {
    // The doctrine claim of "one envelope, optional credential", pinned as bytes.
    expect(VECTOR_CANONICAL.replace(`,"credentialCID":"${VECTOR_CID}"`, '')).toBe(
      VECTOR_IDENTITY_CANONICAL,
    );
    expect(VECTOR_IDENTITY_CANONICAL).not.toContain('credentialCID');
  });

  it('emits &, < and > LITERALLY in the five-member form too', () => {
    const canonical = decoder.decode(
      apiIdentitySigningInput(vectorIdentityPayload('/v0/profile?q=<a>&b=2')),
    );
    expect(canonical).toContain('"path":"/v0/profile?q=<a>&b=2"');
    for (const escape of ['\\u0026', '\\u003c', '\\u003e']) {
      expect(canonical).not.toContain(escape);
    }
  });

  it('pins the signed identity-proof vector, and the payload segment IS the signing input', async () => {
    const { proof } = await signApiIdentityRequest({
      method: 'GET',
      host: 'api.dfos.com',
      path: '/v0/profile',
      kid: VECTOR_KID,
      sign: vectorSigner(),
      iat: VECTOR_IAT,
    });
    expect(proof).toBe(VECTOR_IDENTITY_JWS);
    expect(proof.split('.')[1]).toBe(
      base64urlEncode(apiIdentitySigningInput(vectorIdentityPayload('/v0/profile'))),
    );
    // The header carries the identity typ, and the two vectors are NOT the same
    // token: the typ is under the signature.
    const header = JSON.parse(decoder.decode(base64urlDecode(proof.split('.')[0]!))) as Record<
      string,
      unknown
    >;
    expect(header['typ']).toBe(IDENTITY_PROOF_JWS_TYP);
    expect(proof).not.toBe(VECTOR_JWS);
  });

  it('applies the SAME member rules — one fewer member, not a relaxation', () => {
    const base = vectorIdentityPayload('/v0/profile');
    const vectors: Array<[string, IdentityProofPayload]> = [
      ['lowercase method', { ...base, method: 'get' }],
      ['mixed-case method', { ...base, method: 'GeT' }],
      ['empty method', { ...base, method: '' }],
      ['uppercase host', { ...base, host: 'API.dfos.com' }],
      ['host with scheme', { ...base, host: 'https://api.dfos.com' }],
      ['relative path', { ...base, path: 'v0/profile' }],
      ['path with fragment', { ...base, path: '/v0/profile#top' }],
      ['path with a space', { ...base, path: '/v0/pro file' }],
      ['padded bodyHash', { ...base, bodyHash: `${EMPTY_BODY_SHA256}=` }],
      ['short bodyHash', { ...base, bodyHash: EMPTY_BODY_SHA256.slice(0, 42) }],
      [
        'non-canonical bodyHash spelling',
        { ...base, bodyHash: `${EMPTY_BODY_SHA256.slice(0, -1)}V` },
      ],
      ['zero iat', { ...base, iat: 0 }],
      ['negative iat', { ...base, iat: -1 }],
      ['fractional iat', { ...base, iat: 1772841600.5 }],
    ];
    for (const [name, payload] of vectors) {
      expect(() => apiIdentitySigningInput(payload), name).toThrow();
    }
  });
});

describe('signApiIdentityRequest', () => {
  it('hashes the body, defaults iat to now, and refuses a kid that is not a DID URL', async () => {
    const signed = await signApiIdentityRequest({
      method: 'POST',
      host: 'api.dfos.com',
      path: '/v0/profile',
      body: encoder.encode('{"a":1}'),
      kid: VECTOR_KID,
      sign: vectorSigner(),
    });
    expect(signed.payload.bodyHash).toBe(VECTOR_BODY_HASH);
    expect(signed.payload.iat).toBeGreaterThan(1_700_000_000);
    expect(signed.proof.length).toBeLessThanOrEqual(MAX_REQUEST_PROOF_SIZE);

    await expect(
      signApiIdentityRequest({
        method: 'GET',
        host: 'api.dfos.com',
        path: '/v0/profile',
        kid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
        sign: vectorSigner(),
      }),
    ).rejects.toThrow(/DID URL/);
  });

  it('builds the ONE carriage header — no X-Credential rides an identity proof', () => {
    const headers = buildApiIdentityHeaders({ proof: VECTOR_IDENTITY_JWS });
    expect(headers.Authorization).toBe(`DFOS ${VECTOR_IDENTITY_JWS}`);
    expect(headers.Authorization).not.toMatch(/Bearer/);
    expect(Object.keys(headers)).toEqual(['Authorization']);
  });
});

describe('signApiRequest', () => {
  it('hashes the body, defaults iat to now, and refuses a kid that is not a DID URL', async () => {
    const signed = await signApiRequest({
      method: 'POST',
      host: 'api.dfos.com',
      path: '/v0/profile',
      body: encoder.encode('{"a":1}'),
      credentialCID: VECTOR_CID,
      kid: VECTOR_KID,
      sign: vectorSigner(),
    });
    expect(signed.payload.bodyHash).toBe(VECTOR_BODY_HASH);
    expect(signed.payload.iat).toBeGreaterThan(1_700_000_000);
    expect(signed.proof.length).toBeLessThanOrEqual(MAX_REQUEST_PROOF_SIZE);

    await expect(
      signApiRequest({
        method: 'GET',
        host: 'api.dfos.com',
        path: '/v0/profile',
        credentialCID: VECTOR_CID,
        kid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
        sign: vectorSigner(),
      }),
    ).rejects.toThrow(/DID URL/);
  });

  it('builds the two carriage headers, with the DFOS scheme and not Bearer', () => {
    const headers = buildApiAuthHeaders({ proof: VECTOR_JWS, credential: 'credential-jws' });
    expect(headers.Authorization).toBe(`DFOS ${VECTOR_JWS}`);
    expect(headers.Authorization).not.toMatch(/Bearer/);
    expect(headers['X-Credential']).toBe('credential-jws');
  });
});

// -----------------------------------------------------------------------------
// verify — the full eleven steps
// -----------------------------------------------------------------------------

const HOST = 'api.dfos.com';
const NOW = Math.floor(Date.now() / 1000);

/** Replace one char with a guaranteed-different one — a byte-level tamper that
 *  can never round-trip to the original string. */
const tamperOneChar = (s: string, index: number): string =>
  `${s.slice(0, index)}${s[index] === 'A' ? 'B' : 'A'}${s.slice(index + 1)}`;
const API_ATT: Attenuation[] = [{ resource: `api:${HOST}`, action: DEFAULT_API_ACTION }];

type Identity = Awaited<ReturnType<typeof buildIdentity>>;

const clientFor = (identities: Identity[], isRevoked?: RevChecker) =>
  createClient({
    relays: [RELAY],
    peerClient: fakePeerClient({
      [RELAY]: {
        identities: Object.fromEntries(identities.map((id) => [id.did, id.log])),
      },
    }),
    ...(isRevoked ? { isRevoked } : {}),
  });

const issueCredential = async (input: {
  issuer: Identity;
  aud: string;
  att?: Attenuation[];
  prf?: string[];
  exp?: number;
}): Promise<{ jws: string; cid: string }> => {
  const jws = await createDFOSCredential({
    issuerDID: input.issuer.did,
    audienceDID: input.aud,
    att: input.att ?? API_ATT,
    prf: input.prf ?? [],
    exp: input.exp ?? NOW + 86_400,
    signer: input.issuer.k.signer,
    keyId: input.issuer.k.keyId,
    iat: NOW - 600,
  });
  return { jws, cid: cidOf(jws) };
};

/** The honest happy path: user → RP credential, RP signs a proof over the request. */
const buildGrant = async (
  overrides: { att?: Attenuation[]; host?: string } = {},
): Promise<{
  user: Identity;
  rp: Identity;
  credential: string;
  credentialCID: string;
  proof: string;
}> => {
  const user = await buildIdentity();
  const rp = await buildIdentity();
  const host = overrides.host ?? HOST;
  const { jws, cid } = await issueCredential({
    issuer: user,
    aud: rp.did,
    ...(overrides.att ? { att: overrides.att } : {}),
  });
  const { proof } = await signApiRequest({
    method: 'GET',
    host,
    path: '/v0/profile',
    credentialCID: cid,
    kid: rp.kid,
    sign: rp.k.signer,
    iat: NOW,
  });
  return { user, rp, credential: jws, credentialCID: cid, proof };
};

const baseInput = (host = HOST) => ({
  method: 'GET',
  host,
  path: '/v0/profile',
  now: () => NOW * 1000,
});

const reasonOf = async (promise: Promise<unknown>): Promise<string> => {
  try {
    await promise;
    return 'resolved';
  } catch (err) {
    return err instanceof ApiRequestVerifyError ? err.reason : `threw ${String(err)}`;
  }
};

const errorOf = async (promise: Promise<unknown>): Promise<ApiRequestVerifyError | undefined> => {
  try {
    await promise;
    return undefined;
  } catch (err) {
    return err instanceof ApiRequestVerifyError ? err : undefined;
  }
};

describe('verifyApiRequest', () => {
  it('verifies a real grant and returns the root iss as the served subject', async () => {
    const grant = await buildGrant();
    const result = await verifyApiRequest(clientFor([grant.user, grant.rp]), {
      ...baseInput(),
      proof: grant.proof,
      credential: grant.credential,
    });
    expect(result.subjectDID).toBe(grant.user.did);
    expect(result.host).toBe(HOST);
    expect(result.action).toBe('read:profile');
    expect(result.iat).toBe(NOW);
    expect(result.credentialCID).toBe(grant.credentialCID);
  });

  it('binds a non-default port in both the proof host and the api: resource', async () => {
    const hostPort = 'api.example.org:8443';
    const user = await buildIdentity();
    const rp = await buildIdentity();
    const { jws, cid } = await issueCredential({
      issuer: user,
      aud: rp.did,
      att: [{ resource: `api:${hostPort}`, action: DEFAULT_API_ACTION }],
    });
    const { proof } = await signApiRequest({
      method: 'GET',
      host: hostPort,
      path: '/v0/profile',
      credentialCID: cid,
      kid: rp.kid,
      sign: rp.k.signer,
      iat: NOW,
    });
    const result = await verifyApiRequest(clientFor([user, rp]), {
      ...baseInput(hostPort),
      proof,
      credential: jws,
    });
    expect(result.host).toBe(hostPort);

    // The SAME proof against the default-port authority must not verify: one
    // hostname serving two API origins would otherwise collapse into one audience.
    expect(
      await reasonOf(
        verifyApiRequest(clientFor([user, rp]), {
          ...baseInput('api.example.org'),
          proof,
          credential: jws,
        }),
      ),
    ).toBe('invalid');
  });

  it('accepts a signature from any current key role, not just authKeys', async () => {
    // The identity fixture registers one key in all three roles; the assertion
    // that matters is that the lookup spans auth + assert + controller per
    // API-AUTH.md ("Any current key role may sign"), unlike SIWD's authKeys-only rule.
    const grant = await buildGrant();
    const client = clientFor([grant.user, grant.rp]);
    const state = (await client.identity(grant.rp.did)).value;
    expect(state.assertKeys.some((key) => key.id === grant.rp.k.keyId)).toBe(true);
    await expect(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: grant.proof,
        credential: grant.credential,
      }),
    ).resolves.toBeTruthy();
  });

  // ---------------------------------------------------------------------------
  // configuration
  // ---------------------------------------------------------------------------

  it('REFUSES a W + S over the 300-second ceiling as a config error, not a verdict', async () => {
    const grant = await buildGrant();
    const client = clientFor([grant.user, grant.rp]);
    const attempt = verifyApiRequest(client, {
      ...baseInput(),
      proof: grant.proof,
      credential: grant.credential,
      windowSeconds: 240,
      skewSeconds: 61,
    });
    expect(await reasonOf(attempt)).toBe('config');
    await expect(attempt).rejects.toThrow(/300 seconds/);

    // Exactly 300 is fine; a negative bound is not.
    await expect(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: grant.proof,
        credential: grant.credential,
        windowSeconds: 240,
        skewSeconds: 60,
      }),
    ).resolves.toBeTruthy();
    expect(
      await reasonOf(
        verifyApiRequest(clientFor([grant.user, grant.rp]), {
          ...baseInput(),
          proof: grant.proof,
          credential: grant.credential,
          skewSeconds: -1,
        }),
      ),
    ).toBe('config');
  });

  // ---------------------------------------------------------------------------
  // envelope, freshness, binding
  // ---------------------------------------------------------------------------

  it('rejects the envelope, freshness, and binding adversarial set', async () => {
    const grant = await buildGrant();
    const oversize = 'a'.repeat(MAX_REQUEST_PROOF_SIZE + 1);

    const queryProof = (
      await signApiRequest({
        method: 'GET',
        host: HOST,
        path: '/v0/profile?a=1&b=2',
        credentialCID: grant.credentialCID,
        kid: grant.rp.kid,
        sign: grant.rp.k.signer,
        iat: NOW,
      })
    ).proof;
    const bodyProof = (
      await signApiRequest({
        method: 'POST',
        host: HOST,
        path: '/v0/profile',
        body: encoder.encode('{"a":1}'),
        credentialCID: grant.credentialCID,
        kid: grant.rp.kid,
        sign: grant.rp.k.signer,
        iat: NOW,
      })
    ).proof;

    const vectors: Array<[string, Parameters<typeof verifyApiRequest>[1]]> = [
      ['oversize proof', { ...baseInput(), proof: oversize, credential: grant.credential }],
      [
        'oversize credential',
        { ...baseInput(), proof: grant.proof, credential: 'c'.repeat(262_145) },
      ],
      ['not a JWS', { ...baseInput(), proof: 'not-a-jws', credential: grant.credential }],
      [
        'wrong-case method',
        { ...baseInput(), method: 'get', proof: grant.proof, credential: grant.credential },
      ],
      [
        'method mismatch',
        { ...baseInput(), method: 'POST', proof: grant.proof, credential: grant.credential },
      ],
      [
        'host mismatch',
        { ...baseInput('api.evil.example'), proof: grant.proof, credential: grant.credential },
      ],
      [
        'query-string mismatch',
        { ...baseInput(), proof: queryProof, credential: grant.credential },
      ],
      [
        'query-parameter reordering is not equivalence',
        {
          ...baseInput(),
          path: '/v0/profile?b=2&a=1',
          proof: queryProof,
          credential: grant.credential,
        },
      ],
      [
        'trailing-slash mismatch',
        { ...baseInput(), path: '/v0/profile/', proof: grant.proof, credential: grant.credential },
      ],
      [
        'body arrived but the proof says empty',
        {
          ...baseInput(),
          body: encoder.encode('{"a":1}'),
          proof: grant.proof,
          credential: grant.credential,
        },
      ],
      [
        'body dropped from a body-bearing proof',
        { ...baseInput(), method: 'POST', proof: bodyProof, credential: grant.credential },
      ],
      [
        'stale iat',
        {
          ...baseInput(),
          proof: grant.proof,
          credential: grant.credential,
          now: () => (NOW + 61) * 1000,
        },
      ],
      [
        'forward-dated iat',
        {
          ...baseInput(),
          proof: grant.proof,
          credential: grant.credential,
          now: () => (NOW - 61) * 1000,
        },
      ],
    ];

    for (const [name, input] of vectors) {
      expect(await reasonOf(verifyApiRequest(clientFor([grant.user, grant.rp]), input)), name).toBe(
        'invalid',
      );
    }
  });

  it('bounds AGE and FORWARD SKEW separately', async () => {
    const grant = await buildGrant();
    const tight = { windowSeconds: 30, skewSeconds: 5 };
    const at = (offset: number) => ({
      ...baseInput(),
      proof: grant.proof,
      credential: grant.credential,
      ...tight,
      now: () => (NOW + offset) * 1000,
    });

    // 20s old is inside W=30. 20s forward-dated is also inside W — and a
    // symmetric |now - iat| <= W would have accepted it. S=5 is what refuses it.
    await expect(verifyApiRequest(clientFor([grant.user, grant.rp]), at(20))).resolves.toBeTruthy();
    expect(await reasonOf(verifyApiRequest(clientFor([grant.user, grant.rp]), at(-20)))).toBe(
      'invalid',
    );
    // Both boundaries are inclusive.
    await expect(verifyApiRequest(clientFor([grant.user, grant.rp]), at(30))).resolves.toBeTruthy();
    await expect(verifyApiRequest(clientFor([grant.user, grant.rp]), at(-5))).resolves.toBeTruthy();
  });

  it('honors an explicit W = 0 rather than defaulting it', async () => {
    const grant = await buildGrant();
    const at = (offset: number) => ({
      ...baseInput(),
      proof: grant.proof,
      credential: grant.credential,
      windowSeconds: 0,
      skewSeconds: 0,
      now: () => (NOW + offset) * 1000,
    });
    // At exactly iat, W=0 accepts. 1s old is stale — a defaulted W=60 would accept.
    await expect(verifyApiRequest(clientFor([grant.user, grant.rp]), at(0))).resolves.toBeTruthy();
    expect(await reasonOf(verifyApiRequest(clientFor([grant.user, grant.rp]), at(1)))).toBe(
      'invalid',
    );
  });

  it('refuses an over-cap body before hashing it (413), and honors maxBodyBytes', async () => {
    const grant = await buildGrant();
    // A proof whose bodyHash matches a large body, presented with maxBodyBytes
    // below that body: refused at 413 before the SHA-256, not accepted.
    const big = new Uint8Array(64);
    const { proof } = await signApiRequest({
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      body: big,
      credentialCID: grant.credentialCID,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      iat: NOW,
    });
    const err = await errorOf(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof,
        credential: grant.credential,
        body: big,
        maxBodyBytes: 32,
      }),
    );
    expect(err?.reason).toBe('invalid');
    expect(err?.phase).toBe('proof');
    expect(err?.status).toBe(413);
  });

  it('refuses an empty required action as config, never as an authorized request', async () => {
    // An action that canonicalizes to the empty set is a subset of every grant's
    // action set — a misconfigured route would authorize any api:<host> holder.
    const grant = await buildGrant();
    for (const action of ['', '  ', ',', ' , ']) {
      const err = await errorOf(
        verifyApiRequest(clientFor([grant.user, grant.rp]), {
          ...baseInput(),
          proof: grant.proof,
          credential: grant.credential,
          action,
        }),
      );
      expect(err?.reason, JSON.stringify(action)).toBe('config');
      expect(err?.status).toBe(500);
    }
  });

  it('carries the phase and HTTP status so 401 vs 403 needs no message parsing', async () => {
    const grant = await buildGrant();
    // A proof-layer failure (bad size) → invalid / proof / 401.
    const proofErr = await errorOf(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: 'x'.repeat(MAX_REQUEST_PROOF_SIZE + 1),
        credential: grant.credential,
      }),
    );
    expect(proofErr?.reason).toBe('invalid');
    expect(proofErr?.phase).toBe('proof');
    expect(proofErr?.status).toBe(401);
    // A credential-layer failure (wrong host → coverage miss is credential-phase;
    // here a host mismatch is proof-phase, so use a coverage miss instead): ask
    // for an action the grant does not carry.
    const credErr = await errorOf(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: grant.proof,
        credential: grant.credential,
        action: 'read:posts',
      }),
    );
    expect(credErr?.reason).toBe('invalid');
    expect(credErr?.phase).toBe('credential');
    expect(credErr?.status).toBe(403);
  });

  it('applies the profile header gates and refuses a non-canonical bodyHash on the wire', async () => {
    const grant = await buildGrant();
    const signRaw = async (header: Record<string, unknown>, payload: string): Promise<string> => {
      const signingInput = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(payload)}`;
      const signature = await grant.rp.k.signer(encoder.encode(signingInput));
      return `${signingInput}.${base64urlEncode(signature)}`;
    };
    const canonical = decoder.decode(
      apiRequestSigningInput({
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        bodyHash: EMPTY_BODY_SHA256,
        credentialCID: grant.credentialCID,
        iat: NOW,
      }),
    );
    const good = { alg: 'EdDSA', typ: REQUEST_PROOF_JWS_TYP, kid: grant.rp.kid };

    const vectors: Array<[string, string]> = [
      ['wrong typ', await signRaw({ ...good, typ: 'did:dfos:siwd' }, canonical)],
      ['wrong alg', await signRaw({ ...good, alg: 'HS256' }, canonical)],
      ['crit header', await signRaw({ ...good, crit: ['x'] }, canonical)],
      ['embedded jwk', await signRaw({ ...good, jwk: { kty: 'OKP' } }, canonical)],
      ['kid without a fragment', await signRaw({ ...good, kid: grant.rp.did }, canonical)],
      [
        'padded bodyHash spelling',
        await signRaw(
          good,
          canonical.replace(EMPTY_BODY_SHA256, `${EMPTY_BODY_SHA256.slice(0, 42)}U=`),
        ),
      ],
      [
        'non-canonical bodyHash spelling',
        await signRaw(
          good,
          canonical.replace(EMPTY_BODY_SHA256, `${EMPTY_BODY_SHA256.slice(0, -1)}V`),
        ),
      ],
      ['quoted iat', await signRaw(good, canonical.replace(`"iat":${NOW}`, `"iat":"${NOW}"`))],
      [
        'missing member',
        await signRaw(good, canonical.replace(`,"credentialCID":"${grant.credentialCID}"`, '')),
      ],
      // Tamper mid-signature, not at the tail: the final two base64url chars
      // encode S's high byte, which `S < L` keeps small — it is genuinely 0x00
      // for ~1 in 16 keys, so forcing the tail to "AA" reproduced the original
      // proof byte-for-byte on those runs and the vector verified.
      ['tampered signature', tamperOneChar(grant.proof, grant.proof.length - 10)],
    ];

    for (const [name, proof] of vectors) {
      expect(
        await reasonOf(
          verifyApiRequest(clientFor([grant.user, grant.rp]), {
            ...baseInput(),
            proof,
            credential: grant.credential,
          }),
        ),
        name,
      ).toBe('invalid');
    }

    // Unknown top-level members are IGNORED — the `jti` write-path seam must not
    // make today's verifier reject a well-formed proof.
    const withUnknown = await signRaw(good, `${canonical.slice(0, -1)},"jti":"abc"}`);
    await expect(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: withUnknown,
        credential: grant.credential,
      }),
    ).resolves.toBeTruthy();
  });

  it('rejects a proof signed by a key that is not current, and reports an unresolvable presenter as unverifiable', async () => {
    const grant = await buildGrant();
    const stranger = makeKey();
    const strangerProof = (
      await signApiRequest({
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        credentialCID: grant.credentialCID,
        kid: `${grant.rp.did}#${stranger.keyId}`,
        sign: stranger.signer,
        iat: NOW,
      })
    ).proof;
    expect(
      await reasonOf(
        verifyApiRequest(clientFor([grant.user, grant.rp]), {
          ...baseInput(),
          proof: strangerProof,
          credential: grant.credential,
        }),
      ),
    ).toBe('invalid');

    // A presenter no relay can serve is the SERVER's condition, not the caller's.
    expect(
      await reasonOf(
        verifyApiRequest(clientFor([grant.user]), {
          ...baseInput(),
          proof: grant.proof,
          credential: grant.credential,
        }),
      ),
    ).toBe('unverifiable');
  });

  // ---------------------------------------------------------------------------
  // credential binding + the no-public-audience rule
  // ---------------------------------------------------------------------------

  it('rejects a credentialCID that does not match the presented credential', async () => {
    const grant = await buildGrant();
    const mismatched = (
      await signApiRequest({
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        credentialCID: VECTOR_CID,
        kid: grant.rp.kid,
        sign: grant.rp.k.signer,
        iat: NOW,
      })
    ).proof;
    const attempt = verifyApiRequest(clientFor([grant.user, grant.rp]), {
      ...baseInput(),
      proof: mismatched,
      credential: grant.credential,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/credentialCID/);
  });

  it('rejects a credential audienced to someone other than the proof signer', async () => {
    const user = await buildIdentity();
    const rp = await buildIdentity();
    const other = await buildIdentity();
    const { jws, cid } = await issueCredential({ issuer: user, aud: other.did });
    const { proof } = await signApiRequest({
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      credentialCID: cid,
      kid: rp.kid,
      sign: rp.k.signer,
      iat: NOW,
    });
    const attempt = verifyApiRequest(clientFor([user, rp, other]), {
      ...baseInput(),
      proof,
      credential: jws,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/audience/);
  });

  it('rejects an aud:"*" LEAF — a public credential has no audience to prove possession of', async () => {
    const user = await buildIdentity();
    const rp = await buildIdentity();
    const { jws, cid } = await issueCredential({ issuer: user, aud: '*' });
    const { proof } = await signApiRequest({
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      credentialCID: cid,
      kid: rp.kid,
      sign: rp.k.signer,
      iat: NOW,
    });
    const attempt = verifyApiRequest(clientFor([user, rp]), {
      ...baseInput(),
      proof,
      credential: jws,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/public audience/);
  });

  it('rejects an aud:"*" PARENT — the proof-of-possession bypass', async () => {
    // The attack the leaf-only check misses: a public PARENT satisfies audience
    // linkage for ANY child issuer, so an attacker self-issues a leaf audienced
    // to their own key with the public parent as `prf` and passes the signature,
    // the CID binding, and the leaf-aud check with a key they own.
    const user = await buildIdentity();
    const attacker = await buildIdentity();
    const parent = await issueCredential({ issuer: user, aud: '*' });
    const leaf = await issueCredential({
      issuer: attacker,
      aud: attacker.did,
      prf: [parent.jws],
    });
    const { proof } = await signApiRequest({
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      credentialCID: leaf.cid,
      kid: attacker.kid,
      sign: attacker.k.signer,
      iat: NOW,
    });

    const attempt = verifyApiRequest(clientFor([user, attacker]), {
      ...baseInput(),
      proof,
      credential: leaf.jws,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/public audience/);
  });

  it('verifies a legitimate sub-delegation hop and serves the ROOT iss', async () => {
    const user = await buildIdentity();
    const rp = await buildIdentity();
    const service = await buildIdentity();
    const parent = await issueCredential({ issuer: user, aud: rp.did });
    const leaf = await issueCredential({ issuer: rp, aud: service.did, prf: [parent.jws] });
    const { proof } = await signApiRequest({
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      credentialCID: leaf.cid,
      kid: service.kid,
      sign: service.k.signer,
      iat: NOW,
    });
    const result = await verifyApiRequest(clientFor([user, rp, service]), {
      ...baseInput(),
      proof,
      credential: leaf.jws,
    });
    expect(result.subjectDID).toBe(user.did);
  });

  it('rejects a revoked leaf credential — revocation is checked in the verify path', async () => {
    const grant = await buildGrant();
    const isRevoked: RevChecker = async (_issuer, cid) => cid === grant.credentialCID;
    const attempt = verifyApiRequest(clientFor([grant.user, grant.rp], isRevoked), {
      ...baseInput(),
      proof: grant.proof,
      credential: grant.credential,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/revoked/);
  });

  it('rejects an expired credential on the at-read wall clock', async () => {
    const user = await buildIdentity();
    const rp = await buildIdentity();
    const { jws, cid } = await issueCredential({ issuer: user, aud: rp.did, exp: NOW - 1 });
    const { proof } = await signApiRequest({
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      credentialCID: cid,
      kid: rp.kid,
      sign: rp.k.signer,
      iat: NOW,
    });
    const attempt = verifyApiRequest(clientFor([user, rp]), {
      ...baseInput(),
      proof,
      credential: jws,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/expired/);
  });

  // ---------------------------------------------------------------------------
  // attenuation coverage
  // ---------------------------------------------------------------------------

  it('rejects every attenuation miss, including read:* and action-token case', async () => {
    const vectors: Array<[string, Attenuation[]]> = [
      ['another host', [{ resource: 'api:api.example.org', action: 'read:profile' }]],
      ['another resource type', [{ resource: 'chain:*', action: 'read:profile' }]],
      // `api:*` is an ordinary id covering only itself, which is never a served host.
      ['api wildcard is a literal id', [{ resource: 'api:*', action: 'read:profile' }]],
      // `*` is a LITERAL action token, so `read:*` matches only a route requiring
      // the literal `read:*` — which no route ever will.
      [
        'read:* grant against a read:profile route',
        [{ resource: `api:${HOST}`, action: 'read:*' }],
      ],
      ['uppercase action token', [{ resource: `api:${HOST}`, action: 'READ:PROFILE' }]],
      ['a different action token', [{ resource: `api:${HOST}`, action: 'read:posts' }]],
    ];

    for (const [name, att] of vectors) {
      const grant = await buildGrant({ att });
      const attempt = verifyApiRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: grant.proof,
        credential: grant.credential,
      });
      expect(await reasonOf(attempt), name).toBe('invalid');
      await expect(attempt, name).rejects.toThrow(/does not cover/);
    }
  });

  it('covers a route whose action token is one of several in an enumerated grant', async () => {
    const grant = await buildGrant({
      att: [{ resource: `api:${HOST}`, action: 'read:profile,read:posts' }],
    });
    const result = await verifyApiRequest(clientFor([grant.user, grant.rp]), {
      ...baseInput(),
      proof: grant.proof,
      credential: grant.credential,
      action: 'read:posts',
    });
    expect(result.action).toBe('read:posts');
  });
});

// -----------------------------------------------------------------------------
// verify — the identity proof: the proof phase, and nothing after it
// -----------------------------------------------------------------------------

/** One identity, one proof over the canonical request. No credential anywhere. */
const buildIdentityProof = async (
  overrides: { host?: string; path?: string; iat?: number } = {},
): Promise<{ signer: Identity; proof: string }> => {
  const signer = await buildIdentity();
  const { proof } = await signApiIdentityRequest({
    method: 'GET',
    host: overrides.host ?? HOST,
    path: overrides.path ?? '/v0/profile',
    kid: signer.kid,
    sign: signer.k.signer,
    iat: overrides.iat ?? NOW,
  });
  return { signer, proof };
};

describe('verifyApiIdentityRequest', () => {
  it('verifies a bare identity and returns the SIGNER as the principal', async () => {
    const { signer, proof } = await buildIdentityProof();
    const result = await verifyApiIdentityRequest(clientFor([signer]), {
      ...baseInput(),
      proof,
    });
    expect(result.presenterDID).toBe(signer.did);
    expect(result.host).toBe(HOST);
    expect(result.iat).toBe(NOW);
  });

  it('REJECTS a request proof presented here, and an identity proof presented to verifyApiRequest', async () => {
    // The typ gate, in both directions. "Possession of a grant's audience key" and
    // "possession of a bare identity's key" are different claims, and neither
    // verifier may accept the other's artifact.
    const grant = await buildGrant();
    expect(
      await reasonOf(
        verifyApiIdentityRequest(clientFor([grant.user, grant.rp]), {
          ...baseInput(),
          proof: grant.proof,
        }),
      ),
    ).toBe('invalid');
    await expect(
      verifyApiIdentityRequest(clientFor([grant.user, grant.rp]), {
        ...baseInput(),
        proof: grant.proof,
      }),
    ).rejects.toThrow(/invalid typ/);

    const identity = await buildIdentityProof();
    const attempt = verifyApiRequest(clientFor([identity.signer, grant.user, grant.rp]), {
      ...baseInput(),
      proof: identity.proof,
      credential: grant.credential,
    });
    expect(await reasonOf(attempt)).toBe('invalid');
    await expect(attempt).rejects.toThrow(/invalid typ/);
  });

  it('carries the proof phase and its 401 — there is no 403 tier here', async () => {
    const { signer, proof } = await buildIdentityProof();
    const err = await errorOf(
      verifyApiIdentityRequest(clientFor([signer]), {
        ...baseInput(),
        proof,
        now: () => (NOW + 61) * 1000,
      }),
    );
    expect(err?.reason).toBe('invalid');
    expect(err?.phase).toBe('proof');
    expect(err?.status).toBe(401);
  });

  it('rejects the envelope, freshness, and binding adversarial set', async () => {
    const { signer, proof } = await buildIdentityProof();
    const client = () => clientFor([signer]);
    const signRaw = async (header: Record<string, unknown>, payload: string): Promise<string> => {
      const signingInput = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(payload)}`;
      const signature = await signer.k.signer(encoder.encode(signingInput));
      return `${signingInput}.${base64urlEncode(signature)}`;
    };
    const canonical = decoder.decode(
      apiIdentitySigningInput({
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        bodyHash: EMPTY_BODY_SHA256,
        iat: NOW,
      }),
    );
    const good = { alg: 'EdDSA', typ: IDENTITY_PROOF_JWS_TYP, kid: signer.kid };

    const queryProof = (
      await signApiIdentityRequest({
        method: 'GET',
        host: HOST,
        path: '/v0/profile?a=1&b=2',
        kid: signer.kid,
        sign: signer.k.signer,
        iat: NOW,
      })
    ).proof;
    const bodyProof = (
      await signApiIdentityRequest({
        method: 'POST',
        host: HOST,
        path: '/v0/profile',
        body: encoder.encode('{"a":1}'),
        kid: signer.kid,
        sign: signer.k.signer,
        iat: NOW,
      })
    ).proof;

    const vectors: Array<[string, Parameters<typeof verifyApiIdentityRequest>[1]]> = [
      ['oversize proof', { ...baseInput(), proof: 'a'.repeat(MAX_REQUEST_PROOF_SIZE + 1) }],
      ['not a JWS', { ...baseInput(), proof: 'not-a-jws' }],
      ['wrong-case method', { ...baseInput(), method: 'get', proof }],
      ['method mismatch', { ...baseInput(), method: 'POST', proof }],
      ['host mismatch', { ...baseInput('api.evil.example'), proof }],
      ['host port mismatch', { ...baseInput('api.dfos.com:8443'), proof }],
      ['query-string mismatch', { ...baseInput(), proof: queryProof }],
      [
        'query-parameter reordering is not equivalence',
        { ...baseInput(), path: '/v0/profile?b=2&a=1', proof: queryProof },
      ],
      ['trailing-slash mismatch', { ...baseInput(), path: '/v0/profile/', proof }],
      [
        'body arrived but the proof says empty',
        { ...baseInput(), body: encoder.encode('{"a":1}'), proof },
      ],
      [
        'body dropped from a body-bearing proof',
        { ...baseInput(), method: 'POST', proof: bodyProof },
      ],
      ['stale iat', { ...baseInput(), proof, now: () => (NOW + 61) * 1000 }],
      ['forward-dated iat', { ...baseInput(), proof, now: () => (NOW - 61) * 1000 }],
      ['wrong alg', { ...baseInput(), proof: await signRaw({ ...good, alg: 'HS256' }, canonical) }],
      [
        'crit header',
        { ...baseInput(), proof: await signRaw({ ...good, crit: ['x'] }, canonical) },
      ],
      [
        'embedded jwk',
        { ...baseInput(), proof: await signRaw({ ...good, jwk: { kty: 'OKP' } }, canonical) },
      ],
      [
        'kid without a fragment',
        { ...baseInput(), proof: await signRaw({ ...good, kid: signer.did }, canonical) },
      ],
      [
        'padded bodyHash spelling',
        {
          ...baseInput(),
          proof: await signRaw(
            good,
            canonical.replace(EMPTY_BODY_SHA256, `${EMPTY_BODY_SHA256.slice(0, 42)}U=`),
          ),
        },
      ],
      [
        'non-canonical bodyHash spelling',
        {
          ...baseInput(),
          proof: await signRaw(
            good,
            canonical.replace(EMPTY_BODY_SHA256, `${EMPTY_BODY_SHA256.slice(0, -1)}V`),
          ),
        },
      ],
      [
        'quoted iat',
        {
          ...baseInput(),
          proof: await signRaw(good, canonical.replace(`"iat":${NOW}`, `"iat":"${NOW}"`)),
        },
      ],
      [
        'missing member',
        {
          ...baseInput(),
          proof: await signRaw(good, canonical.replace(`,"bodyHash":"${EMPTY_BODY_SHA256}"`, '')),
        },
      ],
      ['tampered signature', { ...baseInput(), proof: tamperOneChar(proof, proof.length - 10) }],
    ];

    for (const [name, input] of vectors) {
      expect(await reasonOf(verifyApiIdentityRequest(client(), input)), name).toBe('invalid');
    }
  });

  it('IGNORES unknown members, a stray credentialCID included', async () => {
    // The typ gate, not member sniffing, is what tells the two artifacts apart —
    // and the `jti` write-path seam must not make today's verifier reject.
    const { signer } = await buildIdentityProof();
    const canonical = decoder.decode(
      apiIdentitySigningInput({
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        bodyHash: EMPTY_BODY_SHA256,
        iat: NOW,
      }),
    );
    for (const extra of ['"jti":"abc"', `"credentialCID":"${VECTOR_CID}"`]) {
      const signingInput = `${base64urlEncode(
        JSON.stringify({ alg: 'EdDSA', typ: IDENTITY_PROOF_JWS_TYP, kid: signer.kid }),
      )}.${base64urlEncode(`${canonical.slice(0, -1)},${extra}}`)}`;
      const proof = `${signingInput}.${base64urlEncode(
        await signer.k.signer(encoder.encode(signingInput)),
      )}`;
      await expect(
        verifyApiIdentityRequest(clientFor([signer]), { ...baseInput(), proof }),
        extra,
      ).resolves.toBeTruthy();
    }
  });

  it('rejects a key that is not current, and reports an unresolvable presenter as unverifiable', async () => {
    const { signer, proof } = await buildIdentityProof();
    const stranger = makeKey();
    const strangerProof = (
      await signApiIdentityRequest({
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        kid: `${signer.did}#${stranger.keyId}`,
        sign: stranger.signer,
        iat: NOW,
      })
    ).proof;
    expect(
      await reasonOf(
        verifyApiIdentityRequest(clientFor([signer]), { ...baseInput(), proof: strangerProof }),
      ),
    ).toBe('invalid');

    // A presenter no relay can serve is the SERVER's condition, not the caller's —
    // and 503 is the only non-401 verdict this artifact has.
    const err = await errorOf(verifyApiIdentityRequest(clientFor([]), { ...baseInput(), proof }));
    expect(err?.reason).toBe('unverifiable');
    expect(err?.status).toBe(503);
  });

  it('bounds AGE and FORWARD SKEW separately, and refuses W + S over the ceiling', async () => {
    const { signer, proof } = await buildIdentityProof();
    const at = (offset: number) => ({
      ...baseInput(),
      proof,
      windowSeconds: 30,
      skewSeconds: 5,
      now: () => (NOW + offset) * 1000,
    });
    await expect(verifyApiIdentityRequest(clientFor([signer]), at(20))).resolves.toBeTruthy();
    expect(await reasonOf(verifyApiIdentityRequest(clientFor([signer]), at(-20)))).toBe('invalid');
    await expect(verifyApiIdentityRequest(clientFor([signer]), at(30))).resolves.toBeTruthy();
    await expect(verifyApiIdentityRequest(clientFor([signer]), at(-5))).resolves.toBeTruthy();

    const err = await errorOf(
      verifyApiIdentityRequest(clientFor([signer]), {
        ...baseInput(),
        proof,
        windowSeconds: 240,
        skewSeconds: 61,
      }),
    );
    expect(err?.reason).toBe('config');
    expect(err?.status).toBe(500);
    expect(err?.message).toMatch(/300 seconds/);
  });
});

// -----------------------------------------------------------------------------
// createApiAuthFetch — the same byte contract, driven by a Request
// -----------------------------------------------------------------------------

/** A transport that records what it was handed, so the signed Request is inspectable. */
const capturing = (): { calls: Request[]; fetch: typeof fetch } => {
  const calls: Request[] = [];
  return {
    calls,
    fetch: async (input, init) => {
      calls.push(init === undefined && input instanceof Request ? input : new Request(input, init));
      return new Response(null, { status: 204 });
    },
  };
};

const sentProof = (request: Request): string => {
  const authorization = request.headers.get('Authorization');
  if (authorization === null) throw new Error('the signed request carries no Authorization header');
  return authorization.slice('DFOS '.length);
};

const proofPayload = (proof: string): RequestProofPayload => {
  const segment = proof.split('.')[1];
  if (segment === undefined) throw new Error('the proof is not a JWS');
  return JSON.parse(decoder.decode(base64urlDecode(segment))) as RequestProofPayload;
};

describe('createApiAuthFetch', () => {
  it('emits EXACTLY the proof signApiRequest emits for the hand-decomposed request', async () => {
    // The equivalence that makes this an adapter and not a second signer: the
    // adapter's only job is decomposing a Request into the fields below.
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed(new Request('https://api.dfos.com/v0/profile?a=1&b=2'));
    const proof = sentProof(sink.calls[0]!);
    const payload = proofPayload(proof);

    const { proof: expected } = await signApiRequest({
      method: 'GET',
      host: 'api.dfos.com',
      path: '/v0/profile?a=1&b=2',
      credentialCID: grant.credentialCID,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      iat: payload.iat,
    });
    expect(proof).toBe(expected);
  });

  it('carries the query string byte for byte, and reads credentialCID off the credential', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed(new Request('https://api.dfos.com/v0/profile?b=2&a=1'));
    const payload = proofPayload(sentProof(sink.calls[0]!));
    // Not `url.pathname` alone, and not a reordering: dropping or normalizing
    // the query is the classic silent 401.
    expect(payload.path).toBe('/v0/profile?b=2&a=1');
    expect(payload.credentialCID).toBe(grant.credentialCID);
  });

  it('hashes the empty body, and leaves a body-bearing request forwardable', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed(new Request('https://api.dfos.com/v0/profile'));
    expect(proofPayload(sentProof(sink.calls[0]!)).bodyHash).toBe(EMPTY_BODY_SHA256);

    await signed(
      new Request('https://api.dfos.com/v0/profile', { method: 'POST', body: '{"a":1}' }),
    );
    const posted = sink.calls[1]!;
    expect(proofPayload(sentProof(posted)).bodyHash).toBe(VECTOR_BODY_HASH);
    // The proof hashes a CLONE, so the stream handed onward is still unread —
    // buffering the request's own body would forward an empty one.
    expect(posted.bodyUsed).toBe(false);
    expect(await posted.text()).toBe('{"a":1}');
  });

  it('binds the authority WITH its port — url.host, not url.hostname', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed(new Request('https://api.example.org:8443/v0/profile'));
    expect(proofPayload(sentProof(sink.calls[0]!)).host).toBe('api.example.org:8443');

    // The default port is not part of the authority, and must not appear.
    await signed(new Request('https://api.example.org:443/v0/profile'));
    expect(proofPayload(sentProof(sink.calls[1]!)).host).toBe('api.example.org');
  });

  it('sets both carriage headers with the DFOS scheme, preserving the request’s own', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    const response = await signed(
      new Request('https://api.dfos.com/v0/profile', { headers: { Accept: 'application/json' } }),
    );
    const sent = sink.calls[0]!;
    expect(sent.headers.get('Authorization')).toMatch(/^DFOS ey/);
    expect(sent.headers.get('Authorization')).not.toMatch(/Bearer/);
    expect(sent.headers.get('X-Credential')).toBe(grant.credential);
    expect(sent.headers.get('Accept')).toBe('application/json');
    // The underlying transport's response is passed through untouched.
    expect(response.status).toBe(204);
  });

  it('signs a request composed from a URL and init, not only from a Request', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed('https://api.dfos.com/v0/profile', { method: 'POST', body: '{"a":1}' });
    const payload = proofPayload(sentProof(sink.calls[0]!));
    expect(payload.method).toBe('POST');
    expect(payload.path).toBe('/v0/profile');
    expect(payload.bodyHash).toBe(VECTOR_BODY_HASH);
  });

  it('produces a request verifyApiRequest accepts — the whole loop', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed(new Request(`https://${HOST}/v0/profile`));
    const sent = sink.calls[0]!;
    const proof = sentProof(sent);
    const credential = sent.headers.get('X-Credential')!;
    const payload = proofPayload(proof);

    const result = await verifyApiRequest(clientFor([grant.user, grant.rp]), {
      proof,
      credential,
      method: 'GET',
      host: HOST,
      path: '/v0/profile',
      now: () => payload.iat * 1000,
    });
    expect(result.subjectDID).toBe(grant.user.did);
    expect(result.credentialCID).toBe(grant.credentialCID);
  });

  it('REFUSES to sign a plaintext request to a real host, before signing anything', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    let signCalls = 0;
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: async (message) => {
        signCalls += 1;
        return grant.rp.k.signer(message);
      },
      fetch: sink.fetch,
    });

    await expect(signed(new Request('http://api.dfos.com/v0/profile'))).rejects.toThrow(/HTTPS/);
    // Nothing was minted and nothing was sent: a proof that was never signed
    // cannot be captured off a plaintext wire.
    expect(signCalls).toBe(0);
    expect(sink.calls).toHaveLength(0);

    // The lookalike is an ordinary internet host — the check is an exact set,
    // never a suffix test.
    await expect(signed(new Request('http://localhost.evil.example/v0/profile'))).rejects.toThrow(
      /HTTPS/,
    );
    expect(sink.calls).toHaveLength(0);
  });

  it('allows plaintext to loopback, so a local API host is still developable', async () => {
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    for (const origin of ['http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787']) {
      await signed(new Request(`${origin}/v0/profile`));
    }
    expect(sink.calls).toHaveLength(3);
    expect(sink.calls.map((call) => proofPayload(sentProof(call)).host)).toEqual([
      'localhost:8787',
      '127.0.0.1:8787',
      '[::1]:8787',
    ]);
  });

  it('refuses to follow redirects — a 3xx comes back to the caller as-is', async () => {
    // Following one would re-issue the request at coordinates the proof does not
    // cover, and carry X-Credential to whatever authority the Location names.
    const grant = await buildGrant();
    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });

    await signed(new Request('https://api.dfos.com/v0/profile'));
    expect(sink.calls[0]!.redirect).toBe('manual');
  });

  it('sends through globalThis.fetch when no transport is supplied', async () => {
    const grant = await buildGrant();
    // Built BEFORE the stub exists: the default transport is late-bound, so it
    // reads globalThis.fetch at call time rather than capturing it here.
    const signed = createApiAuthFetch({
      credential: grant.credential,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
    });

    const calls: Request[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1],
    ) => {
      calls.push(init === undefined && input instanceof Request ? input : new Request(input, init));
      return new Response(null, { status: 204 });
    }) as typeof fetch;
    try {
      await signed(new Request('https://api.dfos.com/v0/profile'));
    } finally {
      globalThis.fetch = original;
    }

    expect(calls).toHaveLength(1);
    const payload = proofPayload(sentProof(calls[0]!));
    expect(payload.path).toBe('/v0/profile');
    expect(payload.credentialCID).toBe(grant.credentialCID);
  });

  it('a FORGED credential header cid changes no authorization outcome', async () => {
    // The premise the construction-time header read rests on: reading the header
    // trusts the credential holder about its own credential, and an attacker who
    // rewrites that header has broken the signature it is covered by. The adapter
    // duly emits a proof carrying the forged CID; the verifier refuses the request.
    const grant = await buildGrant();
    const parts = grant.credential.split('.');
    const header = JSON.parse(decoder.decode(base64urlDecode(parts[0]!))) as Record<
      string,
      unknown
    >;
    const forged = [
      base64urlEncode(JSON.stringify({ ...header, cid: VECTOR_CID })),
      parts[1],
      parts[2],
    ].join('.');

    const sink = capturing();
    const signed = createApiAuthFetch({
      credential: forged,
      kid: grant.rp.kid,
      sign: grant.rp.k.signer,
      fetch: sink.fetch,
    });
    await signed(new Request(`https://${HOST}/v0/profile`));

    const sent = sink.calls[0]!;
    const proof = sentProof(sent);
    expect(proofPayload(proof).credentialCID).toBe(VECTOR_CID);

    const err = await errorOf(
      verifyApiRequest(clientFor([grant.user, grant.rp]), {
        proof,
        credential: sent.headers.get('X-Credential')!,
        method: 'GET',
        host: HOST,
        path: '/v0/profile',
        now: () => proofPayload(proof).iat * 1000,
      }),
    );
    expect(err?.reason).toBe('invalid');
    expect(err?.phase).toBe('credential');
    expect(err?.status).toBe(403);
  });

  it('refuses a credential with no cid header at CONSTRUCTION, not on the first request', async () => {
    const grant = await buildGrant();
    // A request proof is the artifact most likely to be passed here by mistake,
    // and it deliberately carries no `cid` header at all.
    expect(() =>
      createApiAuthFetch({
        credential: grant.proof,
        kid: grant.rp.kid,
        sign: grant.rp.k.signer,
      }),
    ).toThrow(/cid header/);
    expect(() =>
      createApiAuthFetch({ credential: 'not-a-jws', kid: grant.rp.kid, sign: grant.rp.k.signer }),
    ).toThrow(/decode/);
  });
});
