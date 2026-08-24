/*

  SIWD — byte contract + verification

  The load-bearing piece is `siwdSigningInput`: the PURE bytes both halves share.
  These tests pin the round-trip (mint → encode → decode → same bytes) and the
  no-throw verifier, including the SIWD.md rule that only a CURRENT authKey of a
  non-deleted identity may verify.

*/

import { buildSignRequest } from '@metalabel/dfos-protocol/chain';
import {
  base64urlDecode,
  createJws,
  importEd25519Keypair,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import {
  buildSiwdSignRequest,
  createSiwdChallenge,
  createSiwdLoginRequest,
  decodeSiwdChallenge,
  parseSiwdChallenge,
  readSiwdCallback,
  SIWD_JWS_TYP,
  siwdSigningInput,
  validateSiwdSignRequest,
  verifySiwd,
  type SiwdChallenge,
} from '../src/siwd';
import { memoryStore } from '../src/store/memory';
import { buildIdentity, fakePeerClient, makeKey, ts } from './fixtures';

const RELAY = 'https://relay.test';
const encoder = new TextEncoder();
const siwdTs = (offset = 0): string => ts(offset).replace(/\d{3}Z$/, '000Z');

const signChallenge = async (
  kid: string,
  signer: (m: Uint8Array) => Promise<Uint8Array>,
  challenge: SiwdChallenge,
  typ: string = SIWD_JWS_TYP,
): Promise<string> =>
  createJws({
    header: { alg: 'EdDSA', typ, kid },
    payload: challenge as unknown as Record<string, unknown>,
    sign: signer,
  });

const signRawChallenge = async (
  kid: string,
  signer: (m: Uint8Array) => Promise<Uint8Array>,
  payload: Uint8Array,
  typ: string = SIWD_JWS_TYP,
): Promise<string> => {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ, kid }), 'utf8').toString(
    'base64url',
  );
  const body = Buffer.from(payload).toString('base64url');
  const signingInput = `${header}.${body}`;
  const signature = await signer(encoder.encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
};

describe('siwd byte contract', () => {
  it('round-trips: encoded is base64url(siwdSigningInput(challenge))', () => {
    const { challenge, encoded } = createSiwdChallenge({
      domain: '3p.com',
      statement: 'Sign in to 3P App',
    });
    expect(base64urlDecode(encoded)).toEqual(siwdSigningInput(challenge));
    expect(decodeSiwdChallenge(encoded)).toEqual(challenge);
  });

  it('is deterministic and order-independent across object construction', () => {
    const a: SiwdChallenge = {
      domain: 'x.com',
      nonce: 'n1',
      timestamp: '2026-01-01T00:00:00.000Z',
    };
    const b: SiwdChallenge = {
      timestamp: '2026-01-01T00:00:00.000Z',
      nonce: 'n1',
      domain: 'x.com',
    };
    expect(siwdSigningInput(a)).toEqual(siwdSigningInput(b));
  });

  it('generates a nonce and timestamp when omitted', () => {
    const { challenge, nonce } = createSiwdChallenge({ domain: 'x.com' });
    expect(nonce).toBeTruthy();
    expect(challenge.nonce).toBe(nonce);
    expect(Number.isNaN(Date.parse(challenge.timestamp))).toBe(false);
    expect(challenge.timestamp).toMatch(/\.000Z$/);
  });

  it('pins the shared canonical challenge and signed-artifact vectors', async () => {
    const bare: SiwdChallenge = {
      domain: '3p.com',
      nonce: 'nonce-vector-01',
      timestamp: '2026-08-10T12:34:56.000Z',
    };
    const complete: SiwdChallenge = {
      ...bare,
      statement: 'Sign in to 3P App',
      did: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    };
    expect(new TextDecoder().decode(siwdSigningInput(bare))).toBe(
      '{"domain":"3p.com","nonce":"nonce-vector-01","timestamp":"2026-08-10T12:34:56.000Z"}',
    );
    expect(new TextDecoder().decode(siwdSigningInput(complete))).toBe(
      '{"domain":"3p.com","nonce":"nonce-vector-01","timestamp":"2026-08-10T12:34:56.000Z","statement":"Sign in to 3P App","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"}',
    );

    const keypair = importEd25519Keypair(Uint8Array.from({ length: 32 }, (_, index) => index));
    const token = await createJws({
      header: {
        alg: 'EdDSA',
        typ: SIWD_JWS_TYP,
        kid: `${complete.did}#key_siwd_vector`,
      },
      payload: complete as unknown as Record<string, unknown>,
      sign: async (message) => signPayloadEd25519(message, keypair.privateKey),
    });
    expect(token).toBe(
      'eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnNpd2QiLCJraWQiOiJkaWQ6ZGZvczpuemtmODM4ZWZyNDI0NDMzcm4ycnprZHY4aDd0OWFlI2tleV9zaXdkX3ZlY3RvciJ9.eyJkb21haW4iOiIzcC5jb20iLCJub25jZSI6Im5vbmNlLXZlY3Rvci0wMSIsInRpbWVzdGFtcCI6IjIwMjYtMDgtMTBUMTI6MzQ6NTYuMDAwWiIsInN0YXRlbWVudCI6IlNpZ24gaW4gdG8gM1AgQXBwIiwiZGlkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6a2R2OGg3dDlhZSJ9.52neBNRuHJFbltwI3vx0W5gX2bGkh_zXeHiFaFVRyQr5C0c8fWRtB9_nUf4kp8BahumTZv_J8UuXCQELofHqBQ',
    );
  });

  it('strictly rejects every adversarial non-canonical challenge form', () => {
    const canonical =
      '{"domain":"3p.com","nonce":"nonce-vector-01","timestamp":"2026-08-10T12:34:56.000Z"}';
    const vectors = [
      '{"nonce":"nonce-vector-01","domain":"3p.com","timestamp":"2026-08-10T12:34:56.000Z"}',
      canonical.replace('.000Z', '.123Z'),
      canonical.slice(0, -1) + ',"unknown":"value"}',
      canonical.replace(':"3p.com"', ': "3p.com"'),
      canonical.replace('"domain":"3p.com"', '"domain":"evil.com","domain":"3p.com"'),
      canonical.replace('"nonce":"nonce-vector-01"', '"nonce":""'),
      '[]',
    ];
    for (const vector of vectors) {
      expect(() => parseSiwdChallenge(encoder.encode(vector))).toThrow();
    }
  });

  it('floors caller-supplied timestamps before minting', () => {
    const { challenge } = createSiwdChallenge({
      domain: '3p.com',
      nonce: 'n',
      timestamp: '2026-08-10T12:34:56.999Z',
    });
    expect(challenge.timestamp).toBe('2026-08-10T12:34:56.000Z');
  });
});

describe('siwd login kit', () => {
  const AUTHORIZE = 'https://app.example.com/authorize';

  const paramsOf = (url: string): URLSearchParams => new URL(url).searchParams;

  const clientFor = (id: Awaited<ReturnType<typeof buildIdentity>>) =>
    createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({ [RELAY]: { identities: { [id.did]: id.log } } }),
    });

  it('builds the authorize URL with all four wire params for a public RP', () => {
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
      statement: 'Sign in to 3P App',
      clientDid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    });
    const params = paramsOf(request.url);

    expect(new URL(request.url).origin + new URL(request.url).pathname).toBe(AUTHORIZE);
    expect(params.get('challenge')).toBe(request.challenge);
    expect(params.get('redirect_uri')).toBe('https://3p.com/callback');
    expect(params.get('scope')).toBe('identity');
    expect(params.get('client_did')).toBe('did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae');
  });

  it('preserves a query the authorize endpoint already carries', () => {
    const request = createSiwdLoginRequest({
      authorizeUrl: 'https://app.example.com/authorize?tenant=acme',
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
    });
    const params = paramsOf(request.url);

    expect(params.get('tenant')).toBe('acme');
    expect(params.get('challenge')).toBe(request.challenge);
  });

  it('embeds a challenge that decodes to the returned fields', () => {
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
      statement: 'Sign in to 3P App',
    });

    expect(decodeSiwdChallenge(request.challenge)).toEqual({
      domain: '3p.com',
      nonce: request.expect.nonce,
      timestamp: request.timestamp,
      statement: 'Sign in to 3P App',
    });
    expect(request.timestamp).toMatch(/\.000Z$/);
  });

  /*
    `expect` is the whole persistence story: one JSON-serializable object that
    IS a `SiwdExpectations`, so nothing has to be threaded to both ends of the
    redirect by hand. A `domain` that drifts between mint and verify is a check
    that silently stops checking.
  */
  it('returns an expect object that survives a JSON round trip intact', () => {
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
      nonce: 'persisted-nonce',
    });

    expect(request.expect).toEqual({ domain: '3p.com', nonce: 'persisted-nonce' });
    expect(JSON.parse(JSON.stringify(request.expect))).toEqual(request.expect);
    // absent `did` stays absent rather than serializing as an explicit undefined
    expect('did' in request.expect).toBe(false);
  });

  /*
    Nothing can prove a client DID for an app on a local port, so a host refuses
    a `client_did` on a loopback redirect outright — the whole request, not just
    the param. Dropping it here is what keeps a CLI's sign-in from being a
    guaranteed rejection.
  */
  it.each([
    ['ipv4 loopback with a port', 'http://127.0.0.1:8976/cb'],
    ['localhost with a port', 'http://localhost:3000/'],
    ['bracketed ipv6 loopback', 'http://[::1]:8080/x'],
  ])('omits client_did for a %s redirect even when supplied', (_label, redirectUri) => {
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: 'localhost',
      redirectUri,
      scope: 'identity',
      clientDid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    });

    expect(paramsOf(request.url).get('client_did')).toBeNull();
    expect(paramsOf(request.url).get('redirect_uri')).toBe(redirectUri);
  });

  /*
    A loopback target is admitted for `scope=identity` only (specs/SIWD.md):
    every richer scope returns a credential issued to a `client_did`, which is
    the one param a loopback request cannot carry. Nothing to drop, so it fails
    at build time rather than after a redirect into a guaranteed refusal.
  */
  it('throws on a non-identity scope over a loopback redirect', () => {
    for (const redirectUri of [
      'http://127.0.0.1:8976/cb',
      'http://localhost:3000/',
      'http://[::1]:8080/x',
    ]) {
      expect(() =>
        createSiwdLoginRequest({
          authorizeUrl: AUTHORIZE,
          domain: 'localhost',
          redirectUri,
          scope: 'deposit',
        }),
      ).toThrow(/scope/);
    }

    // …and the admitted scope over the same targets is untouched
    expect(() =>
      createSiwdLoginRequest({
        authorizeUrl: AUTHORIZE,
        domain: 'localhost',
        redirectUri: 'http://127.0.0.1:8976/cb',
        scope: 'identity',
      }),
    ).not.toThrow();

    // a public redirect carries a client_did, so every scope stays open to it
    const hosted = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'deposit',
      clientDid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    });
    expect(paramsOf(hosted.url).get('scope')).toBe('deposit');

    // the lookalike is a public domain: it is entitled to a richer scope too
    expect(() =>
      createSiwdLoginRequest({
        authorizeUrl: AUTHORIZE,
        domain: '127.0.0.1.evil.example',
        redirectUri: 'https://127.0.0.1.evil.example/',
        scope: 'deposit',
      }),
    ).not.toThrow();
  });

  it('keeps client_did for a loopback-LOOKALIKE hostname', () => {
    // `127.0.0.1.evil.example` is a public domain that merely reads as loopback.
    // Matching it would strip an assertion a real registered app is entitled to.
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '127.0.0.1.evil.example',
      redirectUri: 'https://127.0.0.1.evil.example/',
      scope: 'identity',
      clientDid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    });

    expect(paramsOf(request.url).get('client_did')).toBe(
      'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    );
  });

  it('uses a supplied nonce verbatim, and mints one when omitted', () => {
    const supplied = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
      nonce: 'backend-minted-nonce',
    });
    expect(supplied.expect.nonce).toBe('backend-minted-nonce');
    expect(decodeSiwdChallenge(supplied.challenge).nonce).toBe('backend-minted-nonce');

    const minted = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
    });
    expect(minted.expect.nonce).toBeTruthy();
    expect(minted.expect.nonce).not.toBe(supplied.expect.nonce);
  });

  it('throws on an unparseable authorizeUrl or redirectUri', () => {
    expect(() =>
      createSiwdLoginRequest({
        authorizeUrl: '/authorize',
        domain: '3p.com',
        redirectUri: 'https://3p.com/callback',
        scope: 'identity',
      }),
    ).toThrow(/authorizeUrl/);
    expect(() =>
      createSiwdLoginRequest({
        authorizeUrl: AUTHORIZE,
        domain: '3p.com',
        redirectUri: 'not a url',
        scope: 'identity',
      }),
    ).toThrow(/redirectUri/);
  });

  it('composes end to end: mint → sign → read → verify with the persisted expect', async () => {
    const id = await buildIdentity();

    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
      statement: 'Sign in to 3P App',
    });

    // the RP persists `expect` across the redirect, exactly as JSON
    const saved = JSON.parse(JSON.stringify(request.expect));

    // the host decodes the param it was sent and signs those exact bytes
    const challenge = decodeSiwdChallenge(paramsOf(request.url).get('challenge') as string);
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    // …and the RP reads it back off the callback and verifies it
    const callback = readSiwdCallback(
      `https://3p.com/callback?jws=${encodeURIComponent(jws)}&did=${id.did}`,
    );
    expect(callback.kind).toBe('success');
    if (callback.kind !== 'success') throw new Error('expected a success callback');

    const res = await verifySiwd(clientFor(id), callback.jws, saved);
    expect(res.ok).toBe(true);
    expect(res.value?.did).toBe(id.did);
    expect(res.value?.nonce).toBe(request.expect.nonce);
    expect(res.value?.timestamp).toBe(request.timestamp);
  });

  it('round-trips a did-bound request, and rejects a signature from anyone else', async () => {
    const bound = await buildIdentity();
    const stranger = await buildIdentity();

    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: '3p.com',
      redirectUri: 'https://3p.com/callback',
      scope: 'identity',
      did: bound.did,
    });

    // the binding lands in BOTH halves — the signed bytes and the expectation
    const challenge = decodeSiwdChallenge(request.challenge);
    expect(challenge.did).toBe(bound.did);
    expect(request.expect.did).toBe(bound.did);

    const jws = await signChallenge(bound.kid, bound.k.signer, challenge);
    const res = await verifySiwd(clientFor(bound), jws, request.expect);
    expect(res.ok).toBe(true);
    expect(res.value?.did).toBe(bound.did);

    // the whole point of the binding: a different identity signing the same
    // challenge is refused, even though its signature is perfectly valid
    const wrong = await signChallenge(stranger.kid, stranger.k.signer, challenge);
    const rejected = await verifySiwd(clientFor(stranger), wrong, request.expect);
    expect(rejected.ok).toBe(false);
    expect(rejected.error).toMatch(/did/);
  });
});

describe('readSiwdCallback', () => {
  it('reads a success callback', () => {
    expect(readSiwdCallback('https://3p.com/cb?jws=abc.def.ghi&did=did:dfos:xyz')).toEqual({
      kind: 'success',
      jws: 'abc.def.ghi',
      did: 'did:dfos:xyz',
    });
  });

  it('reads a denial', () => {
    expect(readSiwdCallback('https://3p.com/cb?error=access_denied')).toEqual({
      kind: 'denied',
      error: 'access_denied',
    });
  });

  it('reads a bare page load as none', () => {
    expect(readSiwdCallback('https://3p.com/cb')).toEqual({ kind: 'none' });
    expect(readSiwdCallback('https://3p.com/cb?utm_source=x')).toEqual({ kind: 'none' });
  });

  it('reports a half-callback as denied rather than swallowing it', () => {
    expect(readSiwdCallback('https://3p.com/cb?jws=abc.def.ghi')).toEqual({
      kind: 'denied',
      error: 'malformed SIWD callback: missing did',
    });
    expect(readSiwdCallback('https://3p.com/cb?did=did:dfos:xyz')).toEqual({
      kind: 'denied',
      error: 'malformed SIWD callback: missing jws',
    });
  });

  it('treats an empty param value as absent', () => {
    expect(readSiwdCallback('https://3p.com/cb?jws=&did=')).toEqual({ kind: 'none' });
  });

  it('prefers a complete success over a stray error param', () => {
    expect(
      readSiwdCallback('https://3p.com/cb?jws=abc.def.ghi&did=did:dfos:xyz&error=ignored'),
    ).toEqual({ kind: 'success', jws: 'abc.def.ghi', did: 'did:dfos:xyz' });
  });

  it('accepts a URL object as well as a string', () => {
    expect(readSiwdCallback(new URL('https://3p.com/cb?error=access_denied'))).toEqual({
      kind: 'denied',
      error: 'access_denied',
    });
  });

  /*
    `location.search` is what a browser RP has in hand, and it is `''` on a
    plain page load — the single most common path through this function, which
    must not throw.
  */
  it('accepts a bare query string, including the empty one', () => {
    expect(readSiwdCallback('?jws=abc.def.ghi&did=did:dfos:xyz')).toEqual({
      kind: 'success',
      jws: 'abc.def.ghi',
      did: 'did:dfos:xyz',
    });
    expect(readSiwdCallback('?error=access_denied')).toEqual({
      kind: 'denied',
      error: 'access_denied',
    });
    expect(readSiwdCallback('?jws=abc.def.ghi')).toEqual({
      kind: 'denied',
      error: 'malformed SIWD callback: missing did',
    });
    expect(readSiwdCallback('?utm_source=x')).toEqual({ kind: 'none' });
    expect(readSiwdCallback('')).toEqual({ kind: 'none' });
  });

  it('still throws on a string that is neither a URL nor a query', () => {
    expect(() => readSiwdCallback('not a url')).toThrow(/url/);
  });
});

describe('siwd sign-request profile', () => {
  it('builds and validates a canonical family request at the one-clock boundary', async () => {
    const requester = await buildIdentity();
    const subject = await buildIdentity();
    const challenge: SiwdChallenge = {
      domain: '3p.com',
      nonce: 'mailbox-nonce',
      timestamp: '2026-08-10T12:00:00.000Z',
      did: subject.did,
    };
    const built = await buildSiwdSignRequest({
      did: requester.did,
      subject: subject.did,
      challenge,
      acceptanceWindowSeconds: 300,
      createdAt: '2026-08-10T12:00:00.000Z',
      expiresAt: '2026-08-10T12:05:00.999Z',
      signer: requester.k.signer,
      keyId: requester.k.keyId,
    });
    const requesterClient = createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({ [RELAY]: { identities: { [requester.did]: requester.log } } }),
    });
    const validated = await validateSiwdSignRequest(built.jwsToken, {
      signerDid: subject.did,
      acceptanceWindowSeconds: 300,
      resolveIdentity: async (did) =>
        did === requester.did ? (await requesterClient.identity(did)).value : undefined,
      now: Date.parse('2026-08-10T12:01:00.000Z'),
    });
    expect(validated.payloadTyp).toBe(SIWD_JWS_TYP);
    expect(validated.expiresAt).toBe('2026-08-10T12:05:00.000Z');
    expect(validated.challenge).toEqual(challenge);
    expect(validated.payloadBytes).toEqual(siwdSigningInput(challenge));
  });

  it('rejects composer and receiver one-clock violations', async () => {
    const requester = await buildIdentity();
    const subject = await buildIdentity();
    const challenge: SiwdChallenge = {
      domain: '3p.com',
      nonce: 'mailbox-nonce',
      timestamp: '2026-08-10T12:00:00.000Z',
    };
    const common = {
      did: requester.did,
      subject: subject.did,
      challenge,
      acceptanceWindowSeconds: 300,
      createdAt: '2026-08-10T12:00:00.000Z',
      signer: requester.k.signer,
      keyId: requester.k.keyId,
    };
    await expect(
      buildSiwdSignRequest({ ...common, expiresAt: '2026-08-10T12:05:01.000Z' }),
    ).rejects.toThrow(/acceptance window/);

    const incoherent = await buildSignRequest({
      did: requester.did,
      subject: subject.did,
      payloadTyp: SIWD_JWS_TYP,
      payload: siwdSigningInput(challenge),
      createdAt: '2026-08-10T12:00:00.000Z',
      expiresAt: '2026-08-10T12:06:00.000Z',
      signer: requester.k.signer,
      keyId: requester.k.keyId,
    });
    const requesterClient = createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({ [RELAY]: { identities: { [requester.did]: requester.log } } }),
    });
    await expect(
      validateSiwdSignRequest(incoherent.jwsToken, {
        signerDid: subject.did,
        acceptanceWindowSeconds: 300,
        resolveIdentity: async (did) => (await requesterClient.identity(did)).value,
        now: Date.parse('2026-08-10T12:01:00.000Z'),
      }),
    ).rejects.toThrow(/acceptance window/);
  });
});

describe('verifySiwd', () => {
  const clientFor = (id: Awaited<ReturnType<typeof buildIdentity>>) =>
    createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({ [RELAY]: { identities: { [id.did]: id.log } } }),
    });

  it('verifies a challenge signed by a current authKey', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'nonce-1', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'nonce-1' });
    expect(res.ok).toBe(true);
    expect(res.value?.did).toBe(id.did);
    expect(res.value?.kid).toBe(id.kid);
  });

  it('rejects a nonce mismatch', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'issued', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'different' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/nonce/);
  });

  it('rejects a domain mismatch', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: 'evil.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/domain/);
  });

  it('rejects a stale challenge', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(-60) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      nonce: 'n',
      maxAgeSeconds: 300,
    });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/expired/);
  });

  it('rejects a signature from a key that is not a current authKey', async () => {
    const id = await buildIdentity();
    const stranger = makeKey();
    const strangerKid = `${id.did}#${stranger.keyId}`;
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(strangerKid, stranger.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/authentication key/);
  });

  it('rejects when the challenge binds a different did than the signer', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = {
      domain: '3p.com',
      nonce: 'n',
      timestamp: siwdTs(0),
      did: 'did:dfos:someoneelse',
    };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/did/);
  });

  it('rejects a JWS whose typ is not did:dfos:siwd', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge, 'did:dfos:credential');

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/typ/);
  });

  it('strict-validates the original signed payload octets', async () => {
    const id = await buildIdentity();
    const nonCanonical = encoder.encode(
      `{"nonce":"n","domain":"3p.com","timestamp":"${siwdTs(0)}","unknown":"hidden"}`,
    );
    const jws = await signRawChallenge(id.kid, id.k.signer, nonCanonical);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/unknown member/);
  });

  it('rejects a future-dated challenge beyond clock skew', async () => {
    const id = await buildIdentity();
    // timestamp 10 minutes in the future — would pass any maxAge window forever
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(10) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/future/);
  });

  it('rejects a timestamp that does not match the pinned expectation', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      nonce: 'n',
      timestamp: siwdTs(-1),
    });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/timestamp/);
  });

  it('fails CLOSED when the identity resolution is stale, unless allowStale', async () => {
    const id = await buildIdentity();
    const store = memoryStore();
    // warm the cache with a live relay, then go offline — resolution now rests
    // on the cache alone, so "current authKeys" cannot be trusted for auth
    const warm = createClient({
      relays: [RELAY],
      store,
      peerClient: fakePeerClient({ [RELAY]: { identities: { [id.did]: id.log } } }),
    });
    await warm.identity(id.did);
    const offline = createClient({ relays: [RELAY], store, peerClient: fakePeerClient({}) });

    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const closed = await verifySiwd(offline, jws, { domain: '3p.com', nonce: 'n' });
    expect(closed.ok).toBe(false);
    expect(closed.error).toMatch(/stale/);

    // explicit opt-in accepts, and the honest gap rides along on the result
    const opted = await verifySiwd(offline, jws, {
      domain: '3p.com',
      nonce: 'n',
      allowStale: true,
    });
    expect(opted.ok).toBe(true);
    expect(opted.unverifiable).toContain('tip');
  });

  /*
    consumeNonce — the production nonce discipline. Consumption is stateful and
    irreversible, so these pin the two things a caller cannot check for itself:
    the consumer sees exactly the payload nonce, and it is reached only once
    every other check has already passed.
  */
  const spyConsumer = (
    answer: (nonce: string) => boolean | Promise<boolean>,
  ): { fn: (nonce: string) => boolean | Promise<boolean>; calls: string[] } => {
    const calls: string[] = [];
    return {
      fn: (nonce) => {
        calls.push(nonce);
        return answer(nonce);
      },
      calls,
    };
  };

  it('consumes the presented nonce once, and refuses the replay that follows', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = {
      domain: '3p.com',
      nonce: 'minted-1',
      timestamp: siwdTs(0),
    };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);
    // the whole store: what this verifier minted and has not yet spent
    const minted = new Set(['minted-1']);
    const consumer = spyConsumer((nonce) => minted.delete(nonce));

    const res = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      consumeNonce: consumer.fn,
    });
    expect(res.ok).toBe(true);
    expect(res.value?.nonce).toBe('minted-1');
    expect(consumer.calls).toEqual(['minted-1']);

    // the same artifact presented again finds the nonce already spent
    const replay = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      consumeNonce: consumer.fn,
    });
    expect(replay.ok).toBe(false);
    expect(replay.error).toMatch(/nonce/);
    expect(consumer.calls).toEqual(['minted-1', 'minted-1']);
  });

  it('awaits an async consumer', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'async-1', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);
    const consumer = spyConsumer(async (nonce) => nonce === 'async-1');

    const res = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      consumeNonce: consumer.fn,
    });
    expect(res.ok).toBe(true);
    expect(consumer.calls).toEqual(['async-1']);

    const stale = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      consumeNonce: async () => false,
    });
    expect(stale.ok).toBe(false);
    expect(stale.error).toMatch(/nonce/);
  });

  it('fails closed when the consumer throws, carrying its message', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      consumeNonce: () => {
        throw new Error('nonce store unreachable');
      },
    });
    expect(res.ok).toBe(false);
    expect(res.error).toBe('nonce store unreachable');
  });

  /*
    A nonce is spent state, so an otherwise-invalid presentation must never
    reach the consumer: the real user is still holding that nonce, and anyone
    who could make the verifier spend it would have a denial of service on the
    sign-in without producing a signature at all.
  */
  it('never reaches the consumer when an earlier check fails', async () => {
    const id = await buildIdentity();
    const stranger = makeKey();

    // a signature the resolved current authKey does not verify
    const forgedChallenge: SiwdChallenge = {
      domain: '3p.com',
      nonce: 'n',
      timestamp: siwdTs(0),
    };
    const forged = await signChallenge(id.kid, stranger.signer, forgedChallenge);
    const onForged = spyConsumer(() => true);
    const forgedRes = await verifySiwd(clientFor(id), forged, {
      domain: '3p.com',
      consumeNonce: onForged.fn,
    });
    expect(forgedRes.ok).toBe(false);
    expect(forgedRes.error).toMatch(/signature/);
    expect(onForged.calls).toEqual([]);

    // a perfectly signed challenge for someone else's domain
    const wrongDomain = await signChallenge(id.kid, id.k.signer, {
      domain: 'evil.com',
      nonce: 'n',
      timestamp: siwdTs(0),
    });
    const onDomain = spyConsumer(() => true);
    const domainRes = await verifySiwd(clientFor(id), wrongDomain, {
      domain: '3p.com',
      consumeNonce: onDomain.fn,
    });
    expect(domainRes.ok).toBe(false);
    expect(domainRes.error).toMatch(/domain/);
    expect(onDomain.calls).toEqual([]);

    // …and one that is simply too old
    const expired = await signChallenge(id.kid, id.k.signer, {
      domain: '3p.com',
      nonce: 'n',
      timestamp: siwdTs(-60),
    });
    const onExpired = spyConsumer(() => true);
    const expiredRes = await verifySiwd(clientFor(id), expired, {
      domain: '3p.com',
      maxAgeSeconds: 300,
      consumeNonce: onExpired.fn,
    });
    expect(expiredRes.ok).toBe(false);
    expect(expiredRes.error).toMatch(/expired/);
    expect(onExpired.calls).toEqual([]);
  });

  it('rejects an expectation carrying both nonce disciplines, or neither', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: siwdTs(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);
    const consumer = spyConsumer(() => true);

    const both = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      nonce: 'n',
      consumeNonce: consumer.fn,
    });
    expect(both.ok).toBe(false);
    expect(both.error).toMatch(/exactly one/);

    const neither = await verifySiwd(clientFor(id), jws, { domain: '3p.com' });
    expect(neither.ok).toBe(false);
    expect(neither.error).toMatch(/exactly one/);

    // the configuration verdict lands before anything is decoded or spent
    expect(consumer.calls).toEqual([]);
  });
});
