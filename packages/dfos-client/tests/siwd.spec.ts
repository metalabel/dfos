/*

  SIWD — byte contract + verification

  The load-bearing piece is `siwdSigningInput`: the PURE bytes both halves share.
  These tests pin the round-trip (mint → encode → decode → same bytes) and the
  no-throw verifier, including the SIWD.md rule that only a CURRENT authKey of a
  non-deleted identity may verify.

*/

import {
  buildSignRequest,
  decodeMultikey,
  signIdentityOperation,
  verifyIdentityChain,
  type IdentityOperation,
} from '@metalabel/dfos-protocol/chain';
import {
  base64urlDecode,
  base64urlEncode,
  createJws,
  decodeJwsUnsafe,
  importEd25519Keypair,
  signPayloadEd25519,
  verifyJws,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import {
  buildSiwdSignRequest,
  createSiwdChallenge,
  createSiwdLoginRequest,
  createSiwdLoopbackLoginRequest,
  decodeSiwdChallenge,
  encodeSiwdClientChain,
  MAX_SIWD_CLIENT_CHAIN_OPS,
  mintSiwdClientIdentity,
  parseSiwdChallenge,
  readSiwdCallback,
  restoreSiwdClientIdentity,
  signSiwdAskProof,
  SIWD_ASK_JWS_TYP,
  SIWD_JWS_TYP,
  siwdSigningInput,
  validateSiwdSignRequest,
  verifySiwd,
  type SiwdChallenge,
  type SiwdClientIdentity,
} from '../src/siwd';
import { memoryStore } from '../src/store/memory';
import { buildIdentity, cidOf, fakePeerClient, makeKey, ts } from './fixtures';

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
    The loopback credential tier (specs/SIWD.md §Loopback Clients) is what a
    bare `client_did` on a local port used to lack: the request itself proves
    key control. So the param rides through now instead of being dropped — the
    proof that backs it is `createSiwdLoopbackLoginRequest`'s job, not this
    function's.
  */
  it.each([
    ['ipv4 loopback with a port', 'http://127.0.0.1:8976/cb'],
    ['localhost with a port', 'http://localhost:3000/'],
    ['bracketed ipv6 loopback', 'http://[::1]:8080/x'],
  ])('carries client_did for a %s redirect', (_label, redirectUri) => {
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: 'localhost',
      redirectUri,
      scope: 'identity',
      clientDid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    });

    expect(paramsOf(request.url).get('client_did')).toBe(
      'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
    );
    expect(paramsOf(request.url).get('redirect_uri')).toBe(redirectUri);
  });

  /*
    The ANONYMOUS loopback shape is untouched by the tier: no client identity,
    `scope=identity`, and the URL carries exactly the three params it always
    did — no `client_did` conjured from nowhere.
  */
  it('builds the anonymous loopback request with no client_did at all', () => {
    const request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE,
      domain: 'localhost',
      redirectUri: 'http://127.0.0.1:8976/cb',
      scope: 'identity',
    });
    const params = paramsOf(request.url);

    expect(params.get('client_did')).toBeNull();
    expect(params.get('client_proof')).toBeNull();
    expect(params.get('client_chain')).toBeNull();
    expect([...params.keys()].sort()).toEqual(['challenge', 'redirect_uri', 'scope']);
  });

  /*
    A loopback target with NO client identity is admitted for `scope=identity`
    only (specs/SIWD.md): every richer scope returns a credential issued to a
    `client_did`, and there is none to issue to. Naming a client identity opens
    the tier, and with it every scope.
  */
  it('throws on a non-identity loopback scope only when no client identity is named', () => {
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

      // …and naming a client identity lifts the bound HERE. This is the
      // CONSTRUCTOR admitting the shape, not the tier being satisfied: only the
      // composed request — proof, plus chain when the DID is not resident —
      // is one a host will honor. `createSiwdLoopbackLoginRequest` builds that.
      const tiered = createSiwdLoginRequest({
        authorizeUrl: AUTHORIZE,
        domain: 'localhost',
        redirectUri,
        scope: 'deposit',
        clientDid: 'did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae',
      });
      expect(paramsOf(tiered.url).get('scope')).toBe('deposit');
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
    // Classifying it as local would apply the wrong tier's rules to a site that
    // holds a real domain — and can therefore vouch for itself the hosted way.
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

/*

  LOOPBACK CREDENTIAL TIER

  What a `client_did` on a local port now rests on: an ask proof over the
  request's own challenge bytes, and (unless resident) the client's chain.
  These tests replicate the HOST's checks — payload-segment string equality and
  a signature against a current auth key — because those are what the byte
  discipline in `signSiwdAskProof` exists to satisfy.

*/
describe('siwd loopback credential tier', () => {
  const AUTHORIZE = 'https://app.example.com/authorize';
  const paramsOf = (url: string): URLSearchParams => new URL(url).searchParams;

  /** The host's own ask-proof check: typ/alg gate, payload-segment equality
      against its re-derivation, signature against a CURRENT auth key. */
  const hostAcceptsAskProof = async (
    proof: string,
    challenge: SiwdChallenge,
    chain: string[],
  ): Promise<boolean> => {
    const decoded = decodeJwsUnsafe(proof);
    if (!decoded || decoded.header.alg !== 'EdDSA' || decoded.header.typ !== SIWD_ASK_JWS_TYP) {
      return false;
    }
    if (proof.split('.')[1] !== base64urlEncode(siwdSigningInput(challenge))) return false;
    const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: chain });
    return identity.authKeys.some((authKey) => {
      try {
        verifyJws({ token: proof, publicKey: decodeMultikey(authKey.publicKeyMultibase).keyBytes });
        return true;
      } catch {
        return false;
      }
    });
  };

  const askChallenge = (): SiwdChallenge => ({
    domain: 'localhost',
    nonce: 'ask-nonce',
    timestamp: siwdTs(0),
  });

  it('signs an ask proof whose payload segment IS the canonical challenge bytes', async () => {
    const client = await mintSiwdClientIdentity();
    const challenge = askChallenge();
    const proof = await signSiwdAskProof({ challenge, kid: client.kid, signer: client.signer });

    const [headerSegment, payloadSegment] = proof.split('.');
    expect(JSON.parse(new TextDecoder().decode(base64urlDecode(headerSegment as string)))).toEqual({
      alg: 'EdDSA',
      typ: 'did:dfos:siwd-ask',
      kid: client.kid,
    });
    // the host compares this segment as a STRING against its own re-derivation
    expect(payloadSegment).toBe(base64urlEncode(siwdSigningInput(challenge)));
    expect(await hostAcceptsAskProof(proof, challenge, client.chain)).toBe(true);
  });

  it.each([['key_bare'], ['#key_only'], ['did:dfos:x#'], ['#']])(
    'throws on a kid that is not a DID URL with both halves: %s',
    async (kid) => {
      const client = await mintSiwdClientIdentity();
      await expect(
        signSiwdAskProof({ challenge: askChallenge(), kid, signer: client.signer }),
      ).rejects.toThrow(/kid/);
    },
  );

  /*
    The reverse fungibility direction, and the more security-relevant one: a
    SUBJECT's sign-in artifact covers the very same bytes, and only the typ gate
    stops it from being replayed at the host as a client's ask proof.
  */
  it('refuses a subject sign-in presented as an ask proof', async () => {
    const client = await mintSiwdClientIdentity();
    const challenge = askChallenge();
    // same key, same bytes — only the typ differs
    const signIn = await signChallenge(client.kid, client.signer, challenge);

    expect(await hostAcceptsAskProof(signIn, challenge, client.chain)).toBe(false);
  });

  it('refuses an ask proof over a different challenge', async () => {
    const client = await mintSiwdClientIdentity();
    const other: SiwdChallenge = { ...askChallenge(), nonce: 'some-other-nonce' };
    const proof = await signSiwdAskProof({
      challenge: other,
      kid: client.kid,
      signer: client.signer,
    });

    expect(await hostAcceptsAskProof(proof, askChallenge(), client.chain)).toBe(false);
  });

  /*
    Key currency, the host's rule: a key rotated OUT of the chain must not open
    a consent screen, even though its signature is perfectly valid. The fixtures'
    `rotate` ADDS a key without retiring the first, so this builds the stricter
    shape — a successor that REPLACES the genesis key outright.
  */
  const rotatedOutChain = async (): Promise<{ chain: string[]; retired: SiwdClientIdentity }> => {
    const retired = await mintSiwdClientIdentity();
    const successor = makeKey();
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: cidOf(retired.chain[0] as string),
      authKeys: [successor.key],
      assertKeys: [successor.key],
      controllerKeys: [successor.key],
      createdAt: siwdTs(1),
    };
    // signed by the genesis key, which is still a current controller key AT the
    // moment of the update — and is not one afterward
    const signed = await signIdentityOperation({
      operation: update,
      signer: retired.signer,
      keyId: retired.kid.slice(retired.kid.indexOf('#') + 1),
      identityDID: retired.did,
    });
    return { chain: [...retired.chain, signed.jwsToken], retired };
  };

  it('refuses an ask proof signed by a key rotated out of the chain', async () => {
    const { chain, retired } = await rotatedOutChain();
    const challenge = askChallenge();

    // the retired key still signs perfectly well; it is simply not current
    const proof = await signSiwdAskProof({
      challenge,
      kid: retired.kid,
      signer: retired.signer,
    });
    expect(await hostAcceptsAskProof(proof, challenge, retired.chain)).toBe(true);
    expect(await hostAcceptsAskProof(proof, challenge, chain)).toBe(false);
  });

  /*
    The whole point of the distinct typ: the ask proof and a subject's sign-in
    cover the SAME bytes, so only the typ gate keeps one from being presented
    as the other.
  */
  it('produces an artifact verifySiwd refuses — a client ask is not a sign-in', async () => {
    const client = await mintSiwdClientIdentity();
    const challenge = askChallenge();
    const proof = await signSiwdAskProof({ challenge, kid: client.kid, signer: client.signer });

    const resolvable = createClient({
      relays: [RELAY],
      peerClient: fakePeerClient({ [RELAY]: { identities: { [client.did]: client.chain } } }),
    });
    const res = await verifySiwd(resolvable, proof, { domain: 'localhost', nonce: 'ask-nonce' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/typ/);
  });

  it('encodes a carried chain as base64url JSON, genesis first', async () => {
    const client = await mintSiwdClientIdentity();
    const encoded = encodeSiwdClientChain(client.chain);

    expect(JSON.parse(new TextDecoder().decode(base64urlDecode(encoded)))).toEqual(client.chain);
  });

  it('enforces the carriage cap and refuses a log that is not one', () => {
    const filler = (count: number): string[] => Array.from({ length: count }, (_, i) => `op-${i}`);

    // each rejection reports its OWN reason — a caller debugging a refused
    // carriage should not have to guess which of the three it tripped
    expect(() => encodeSiwdClientChain('nope' as unknown as string[])).toThrow(/expected an array/);
    expect(() => encodeSiwdClientChain([])).toThrow(/log is empty/);
    expect(() => encodeSiwdClientChain(['ok', ''])).toThrow(/every member/);
    expect(() => encodeSiwdClientChain(['ok', 42 as unknown as string])).toThrow(/every member/);
    expect(() => encodeSiwdClientChain(filler(MAX_SIWD_CLIENT_CHAIN_OPS + 1))).toThrow(
      /carriage cap/,
    );
    expect(() => encodeSiwdClientChain(filler(MAX_SIWD_CLIENT_CHAIN_OPS))).not.toThrow();
  });

  it('mints a client identity whose chain verifies to the DID it names', async () => {
    const client = await mintSiwdClientIdentity();
    const verified = await verifyIdentityChain({ didPrefix: 'did:dfos', log: client.chain });

    expect(client.chain).toHaveLength(1);
    expect(verified.did).toBe(client.did);
    expect(client.kid).toBe(`${client.did}#${verified.authKeys[0]?.id}`);
    expect(verified.isDeleted).toBe(false);

    // and the returned signer is the current auth key, checked the host's way
    const challenge = askChallenge();
    const proof = await signSiwdAskProof({ challenge, kid: client.kid, signer: client.signer });
    expect(await hostAcceptsAskProof(proof, challenge, client.chain)).toBe(true);
  });

  /*
    The identity is only as durable as its custody: a CLI that cannot restore
    re-mints a DIFFERENT DID every run, re-consents every run, and orphans every
    credential the last run earned. `privateKey` + `chain` is what it persists.
  */
  it('restores a minted identity from privateKey + chain to the same did and kid', async () => {
    const minted = await mintSiwdClientIdentity();
    const restored = await restoreSiwdClientIdentity({
      privateKey: minted.privateKey,
      chain: minted.chain,
    });

    expect(restored.did).toBe(minted.did);
    expect(restored.kid).toBe(minted.kid);
    expect(restored.chain).toEqual(minted.chain);

    // the restored signer is the same key by the only test that matters
    const challenge = askChallenge();
    const proof = await signSiwdAskProof({
      challenge,
      kid: restored.kid,
      signer: restored.signer,
    });
    expect(await hostAcceptsAskProof(proof, challenge, restored.chain)).toBe(true);
  });

  it('refuses to restore a key that does not belong to the chain', async () => {
    const minted = await mintSiwdClientIdentity();
    const stranger = await mintSiwdClientIdentity();

    await expect(
      restoreSiwdClientIdentity({ privateKey: stranger.privateKey, chain: minted.chain }),
    ).rejects.toThrow(/CURRENT authentication key/);
  });

  /*
    Failing at restore, with the reason in hand, beats failing after a redirect:
    a rotated-out key would sign an ask proof the host refuses.
  */
  it('refuses to restore a key the chain has rotated out', async () => {
    const { chain, retired } = await rotatedOutChain();

    // the same key restores fine against the chain that still names it
    await expect(
      restoreSiwdClientIdentity({ privateKey: retired.privateKey, chain: retired.chain }),
    ).resolves.toMatchObject({ did: retired.did });

    await expect(
      restoreSiwdClientIdentity({ privateKey: retired.privateKey, chain }),
    ).rejects.toThrow(/rotated-out key cannot restore/);
  });

  it('builds a loopback request carrying client_did, client_proof, and the chain', async () => {
    const client = await mintSiwdClientIdentity();
    const request = await createSiwdLoopbackLoginRequest({
      authorizeUrl: AUTHORIZE,
      redirectUri: 'http://127.0.0.1:8976/cb',
      scope: 'deposit',
      statement: 'Let dfos-cli deposit on your behalf',
      client,
    });
    const params = paramsOf(request.url);

    expect(params.get('challenge')).toBe(request.challenge);
    expect(params.get('redirect_uri')).toBe('http://127.0.0.1:8976/cb');
    expect(params.get('scope')).toBe('deposit');
    expect(params.get('client_did')).toBe(client.did);
    expect(
      JSON.parse(new TextDecoder().decode(base64urlDecode(params.get('client_chain') ?? ''))),
    ).toEqual(client.chain);

    // the proof covers the request's OWN challenge, byte for byte
    const proof = params.get('client_proof') as string;
    expect(proof.split('.')[1]).toBe(params.get('challenge'));
    expect(
      await hostAcceptsAskProof(proof, decodeSiwdChallenge(request.challenge), client.chain),
    ).toBe(true);
  });

  /*
    The port is not part of the binding — a local application cannot reserve
    one — so SIWD.md pins the challenge domain to the BARE loopback host, which
    is what the host compares literally against the redirect's host.
  */
  it.each([
    ['http://127.0.0.1:8976/cb', '127.0.0.1'],
    ['http://localhost:3000/', 'localhost'],
    ['http://[::1]:8080/x', '::1'],
  ])('derives the challenge domain from %s as the bare host', async (redirectUri, domain) => {
    const client = await mintSiwdClientIdentity();
    const request = await createSiwdLoopbackLoginRequest({
      authorizeUrl: AUTHORIZE,
      redirectUri,
      scope: 'identity',
      client,
    });

    expect(decodeSiwdChallenge(request.challenge).domain).toBe(domain);
    expect(request.expect.domain).toBe(domain);
  });

  it('omits client_chain for a DID already resident on the host', async () => {
    const client = await mintSiwdClientIdentity();
    const request = await createSiwdLoopbackLoginRequest({
      authorizeUrl: AUTHORIZE,
      redirectUri: 'http://localhost:3000/cb',
      scope: 'deposit',
      client: { did: client.did, kid: client.kid, signer: client.signer },
    });
    const params = paramsOf(request.url);

    expect(params.get('client_chain')).toBeNull();
    expect(params.get('client_proof')).toBeTruthy();
    expect(params.get('client_did')).toBe(client.did);
  });

  it('threads a subject binding and a supplied nonce into the signed bytes', async () => {
    const client = await mintSiwdClientIdentity();
    const subject = await buildIdentity();
    const request = await createSiwdLoopbackLoginRequest({
      authorizeUrl: AUTHORIZE,
      redirectUri: 'http://127.0.0.1:8976/cb',
      scope: 'identity',
      did: subject.did,
      nonce: 'cli-minted-nonce',
      client,
    });

    expect(decodeSiwdChallenge(request.challenge)).toEqual({
      domain: '127.0.0.1',
      nonce: 'cli-minted-nonce',
      timestamp: request.timestamp,
      did: subject.did,
    });
    expect(request.expect).toEqual({
      domain: '127.0.0.1',
      nonce: 'cli-minted-nonce',
      did: subject.did,
    });
  });

  it('refuses a redirectUri that is not a loopback target', async () => {
    const client = await mintSiwdClientIdentity();
    await expect(
      createSiwdLoopbackLoginRequest({
        authorizeUrl: AUTHORIZE,
        redirectUri: 'https://3p.com/callback',
        scope: 'deposit',
        client,
      }),
    ).rejects.toThrow(/loopback/);

    // the lookalike is a public domain, not a loopback target either
    await expect(
      createSiwdLoopbackLoginRequest({
        authorizeUrl: AUTHORIZE,
        redirectUri: 'https://127.0.0.1.evil.example/cb',
        scope: 'deposit',
        client,
      }),
    ).rejects.toThrow(/loopback/);
  });

  /*
    SIWD.md defines the loopback interface as `http://` on those hosts. A
    loopback NAME under another scheme is a misconfiguration, and this
    entrypoint is where the claim "I am local software" is made.
  */
  it.each([['https://localhost:9/cb'], ['ftp://127.0.0.1/cb']])(
    'refuses a non-http loopback scheme: %s',
    async (redirectUri) => {
      const client = await mintSiwdClientIdentity();
      await expect(
        createSiwdLoopbackLoginRequest({
          authorizeUrl: AUTHORIZE,
          redirectUri,
          scope: 'deposit',
          client,
        }),
      ).rejects.toThrow(/http:\/\/ loopback/);
    },
  );

  it('refuses a kid that does not belong to the named client did', async () => {
    const client = await mintSiwdClientIdentity();
    const stranger = await mintSiwdClientIdentity();

    await expect(
      createSiwdLoopbackLoginRequest({
        authorizeUrl: AUTHORIZE,
        redirectUri: 'http://127.0.0.1:8976/cb',
        scope: 'deposit',
        client: { did: client.did, kid: stranger.kid, signer: stranger.signer },
      }),
    ).rejects.toThrow(/client\.kid/);
  });

  /*
    The whole loop, mirroring the profile-A end-to-end test one describe up:
    mint → compose → the host's checks → callback with a fragment credential →
    verify. The nonce is CONSUMED, not compared: SIWD.md requires consumed
    verification for every credential-returning scope, and a loopback verifier
    is that discipline with a store of size one.
  */
  it('composes end to end: mint → ask → host checks → callback → verify', async () => {
    const app = await mintSiwdClientIdentity();
    const subject = await buildIdentity();

    const request = await createSiwdLoopbackLoginRequest({
      authorizeUrl: AUTHORIZE,
      redirectUri: 'http://127.0.0.1:8976/cb',
      scope: 'deposit',
      client: app,
    });
    const params = paramsOf(request.url);

    // — the host's half: verify the ask before rendering any consent —
    const challenge = decodeSiwdChallenge(params.get('challenge') as string);
    const carried = JSON.parse(
      new TextDecoder().decode(base64urlDecode(params.get('client_chain') as string)),
    ) as string[];
    const carriedIdentity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: carried });
    expect(carriedIdentity.did).toBe(params.get('client_did'));
    expect(
      await hostAcceptsAskProof(params.get('client_proof') as string, challenge, carried),
    ).toBe(true);

    // consent granted: the subject signs, and the host returns a credential in
    // the FRAGMENT and the sign-in JWS in the query
    const jws = await signChallenge(subject.kid, subject.k.signer, challenge);
    const callback = readSiwdCallback(
      `http://127.0.0.1:8976/cb?jws=${encodeURIComponent(jws)}&did=${subject.did}` +
        `#credential=${encodeURIComponent('cre.den.tial')}`,
    );
    expect(callback.kind).toBe('success');
    if (callback.kind !== 'success') throw new Error('expected a success callback');
    expect(callback.credential).toBe('cre.den.tial');

    // — the client's half: a consumed store of size one —
    let outstanding: string | undefined = request.expect.nonce;
    const consumeNonce = (nonce: string): boolean => {
      if (outstanding === undefined || nonce !== outstanding) return false;
      outstanding = undefined;
      return true;
    };
    // a fresh client per verification: a reused one answers the second call
    // from its own warm cache, which auth refuses before it reaches the nonce
    const subjectClient = () =>
      createClient({
        relays: [RELAY],
        peerClient: fakePeerClient({ [RELAY]: { identities: { [subject.did]: subject.log } } }),
      });

    const session = await verifySiwd(subjectClient(), callback.jws, {
      domain: request.expect.domain,
      consumeNonce,
    });
    expect(session.ok).toBe(true);
    expect(session.value?.did).toBe(subject.did);

    // and the store of size one is spent — the replay finds nothing
    const replay = await verifySiwd(subjectClient(), callback.jws, {
      domain: request.expect.domain,
      consumeNonce,
    });
    expect(replay.ok).toBe(false);
    expect(replay.error).toMatch(/nonce/);
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

  /*
    A credential rides the FRAGMENT so it is never sent to a server — no access
    log, no proxy log, no Referer. Reading it therefore takes the whole URL.
  */
  it('lifts a credential out of the fragment on a success callback', () => {
    expect(
      readSiwdCallback(
        'https://3p.com/cb?jws=abc.def.ghi&did=did:dfos:xyz#credential=cre.den.tial',
      ),
    ).toEqual({
      kind: 'success',
      jws: 'abc.def.ghi',
      did: 'did:dfos:xyz',
      credential: 'cre.den.tial',
    });

    expect(
      readSiwdCallback(
        new URL('http://127.0.0.1:8976/cb?jws=a.b.c&did=did:dfos:xyz#credential=c.r.e&x=1'),
      ),
    ).toEqual({ kind: 'success', jws: 'a.b.c', did: 'did:dfos:xyz', credential: 'c.r.e' });
  });

  it('reads a success with no fragment, and an empty credential, as no credential', () => {
    expect(readSiwdCallback('https://3p.com/cb?jws=a.b.c&did=did:dfos:xyz')).toEqual({
      kind: 'success',
      jws: 'a.b.c',
      did: 'did:dfos:xyz',
    });
    expect(readSiwdCallback('https://3p.com/cb?jws=a.b.c&did=did:dfos:xyz#credential=')).toEqual({
      kind: 'success',
      jws: 'a.b.c',
      did: 'did:dfos:xyz',
    });
  });

  it('yields no credential from a query string that has no fragment', () => {
    expect(readSiwdCallback('?jws=a.b.c&did=did:dfos:xyz')).toEqual({
      kind: 'success',
      jws: 'a.b.c',
      did: 'did:dfos:xyz',
    });
  });

  /*
    `URLSearchParams` does not treat `#` as a delimiter, so a caller who
    concatenated `location.search + location.hash` — the natural reach once the
    docs say the credential is in the fragment — would otherwise read `did` as
    `did:dfos:xyz#credential=…` and lose the credential entirely.
  */
  it('splits a bare `?query#fragment` string instead of corrupting did', () => {
    expect(readSiwdCallback('?jws=a.b.c&did=did:dfos:xyz#credential=cre.den.tial')).toEqual({
      kind: 'success',
      jws: 'a.b.c',
      did: 'did:dfos:xyz',
      credential: 'cre.den.tial',
    });

    // an empty fragment is no fragment, and must not bleed into `did` either
    expect(readSiwdCallback('?jws=a.b.c&did=did:dfos:xyz#')).toEqual({
      kind: 'success',
      jws: 'a.b.c',
      did: 'did:dfos:xyz',
    });
  });

  /*
    The query half's verdict wins: a stray fragment on a non-callback load is
    noise, not a session, and there is no half-callback state to promote.
  */
  it('does not let a fragment credential change a denied or none verdict', () => {
    expect(readSiwdCallback('https://3p.com/cb?error=access_denied#credential=c.r.e')).toEqual({
      kind: 'denied',
      error: 'access_denied',
    });
    expect(readSiwdCallback('https://3p.com/cb#credential=c.r.e')).toEqual({ kind: 'none' });
    expect(readSiwdCallback('https://3p.com/cb?jws=a.b.c#credential=c.r.e')).toEqual({
      kind: 'denied',
      error: 'malformed SIWD callback: missing did',
    });
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
