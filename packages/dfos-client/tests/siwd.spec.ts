/*

  SIWD — byte contract + verification

  The load-bearing piece is `siwdSigningInput`: the PURE bytes both halves share.
  These tests pin the round-trip (mint → encode → decode → same bytes) and the
  no-throw verifier, including the SIWD.md rule that only a CURRENT authKey of a
  non-deleted identity may verify.

*/

import { base64urlDecode, createJws } from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import {
  createSiwdChallenge,
  decodeSiwdChallenge,
  SIWD_JWS_TYP,
  siwdSigningInput,
  verifySiwd,
  type SiwdChallenge,
} from '../src/siwd';
import { memoryStore } from '../src/store/memory';
import { buildIdentity, fakePeerClient, makeKey, ts } from './fixtures';

const RELAY = 'https://relay.test';

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
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'nonce-1', timestamp: ts(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'nonce-1' });
    expect(res.ok).toBe(true);
    expect(res.value?.did).toBe(id.did);
    expect(res.value?.kid).toBe(id.kid);
  });

  it('rejects a nonce mismatch', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'issued', timestamp: ts(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'different' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/nonce/);
  });

  it('rejects a domain mismatch', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: 'evil.com', nonce: 'n', timestamp: ts(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/domain/);
  });

  it('rejects a stale challenge', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: ts(-60) };
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
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: ts(0) };
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
      timestamp: ts(0),
      did: 'did:dfos:someoneelse',
    };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/did/);
  });

  it('rejects a JWS whose typ is not did:dfos:siwd', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: ts(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge, 'did:dfos:credential');

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/typ/);
  });

  it('rejects a future-dated challenge beyond clock skew', async () => {
    const id = await buildIdentity();
    // timestamp 10 minutes in the future — would pass any maxAge window forever
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: ts(10) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, { domain: '3p.com', nonce: 'n' });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/future/);
  });

  it('rejects a timestamp that does not match the pinned expectation', async () => {
    const id = await buildIdentity();
    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: ts(0) };
    const jws = await signChallenge(id.kid, id.k.signer, challenge);

    const res = await verifySiwd(clientFor(id), jws, {
      domain: '3p.com',
      nonce: 'n',
      timestamp: ts(-1),
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

    const challenge: SiwdChallenge = { domain: '3p.com', nonce: 'n', timestamp: ts(0) };
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
