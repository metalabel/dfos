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
  base64urlEncode,
  importEd25519Keypair,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import {
  apiRequestSigningInput,
  ApiRequestVerifyError,
  buildApiAuthHeaders,
  DEFAULT_API_ACTION,
  EMPTY_BODY_SHA256,
  MAX_REQUEST_PROOF_SIZE,
  REQUEST_PROOF_JWS_TYP,
  sha256BodyHash,
  signApiRequest,
  verifyApiRequest,
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
      ['tampered signature', `${grant.proof.slice(0, -2)}AA`],
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
