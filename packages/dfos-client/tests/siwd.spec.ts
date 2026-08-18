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
  decodeSiwdChallenge,
  parseSiwdChallenge,
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
});
