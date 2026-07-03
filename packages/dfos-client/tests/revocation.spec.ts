/*

  REVOCATION CHECKER — believe the proof, never the boolean

  A relay's `revoked: true` answer is only as good as the revocation JWS it
  carries. These tests pin the zero-trust rules: the proof must VERIFY through
  the protocol's verifyRevocation (signature against the issuer's resolved key,
  CID integrity, issuer-only rule) AND bind exactly the queried
  (issuerDID, credentialCID) pair — forged JWSs and cross-credential replays
  prove nothing. Negative and unusable answers keep consulting the rest of the
  relay set; false only after all relays have been asked.

*/

import { decodeMultikey, signRevocation } from '@metalabel/dfos-protocol/chain';
import { createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import { createRevocationChecker } from '../src/revocation';
import { buildIdentity, fakePeerClient, type BuiltIdentity } from './fixtures';

const A = 'https://a.test';
const B = 'https://b.test';

/** resolveKey over a set of fixture identities (kid → key bytes). */
const resolveKeyFor =
  (...ids: BuiltIdentity[]) =>
  async (kid: string): Promise<Uint8Array> => {
    const match = ids.find((id) => kid === id.kid);
    if (!match) throw new Error(`unknown kid ${kid}`);
    return decodeMultikey(match.k.key.publicKeyMultibase).keyBytes;
  };

/** A fetch fake serving /revocations/v1/credential/:cid per-relay bodies. */
const revocationFetch =
  (byUrl: Record<string, Record<string, unknown>>): typeof fetch =>
  async (input) => {
    const url = String(input);
    const origin = new URL(url).origin;
    const body = byUrl[origin]?.[url.split('/credential/')[1] ?? ''];
    if (body === undefined) return new Response('{"error":"not found"}', { status: 404 });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

const credCid = (jws: string): string => {
  const decoded = decodeJwsUnsafe(jws);
  return typeof decoded?.header.cid === 'string' ? decoded.header.cid : '';
};

describe('createRevocationChecker', () => {
  const setup = async () => {
    const issuer = await buildIdentity();
    const credential = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'read' }],
      exp: Math.floor(Date.now() / 1000) + 3600,
      signer: issuer.k.signer,
      keyId: issuer.k.keyId,
    });
    const credentialCID = credCid(credential);
    const revocation = await signRevocation({
      issuerDID: issuer.did,
      credentialCID,
      signer: issuer.k.signer,
      keyId: issuer.k.keyId,
    });
    return { issuer, credential, credentialCID, revocation };
  };

  it('accepts a genuine, verified revocation bound to the queried credential', async () => {
    const { issuer, credentialCID, revocation } = await setup();
    const isRevoked = createRevocationChecker(
      [A],
      revocationFetch({
        [A]: { [credentialCID]: { revoked: true, revocation: revocation.jwsToken } },
      }),
      resolveKeyFor(issuer),
    );
    expect(await isRevoked(issuer.did, credentialCID)).toBe(true);
  });

  it('rejects a forged (unverifiable) revocation JWS — the boolean is never believed', async () => {
    const { issuer, credentialCID } = await setup();
    const isRevoked = createRevocationChecker(
      [A],
      revocationFetch({
        [A]: { [credentialCID]: { revoked: true, revocation: 'eyJmb3JnZWQ.eyJkaWQ.c2ln' } },
      }),
      resolveKeyFor(issuer),
    );
    expect(await isRevoked(issuer.did, credentialCID)).toBe(false);
  });

  it('rejects a REAL revocation replayed for a DIFFERENT credential', async () => {
    const { issuer, revocation } = await setup();
    // the relay returns a genuine, verifiable revocation — but for another CID
    const otherCID = 'bafyrei' + 'a'.repeat(52);
    const isRevoked = createRevocationChecker(
      [A],
      revocationFetch({
        [A]: { [otherCID]: { revoked: true, revocation: revocation.jwsToken } },
      }),
      resolveKeyFor(issuer),
    );
    expect(await isRevoked(issuer.did, otherCID)).toBe(false);
  });

  it("rejects a revocation whose issuer is not the credential's issuer", async () => {
    const { credentialCID } = await setup();
    // a different identity signs a (self-consistent) revocation for the same CID —
    // it verifies as ITS OWN, but does not bind the queried issuer
    const impostor = await buildIdentity();
    const impostorRevocation = await signRevocation({
      issuerDID: impostor.did,
      credentialCID,
      signer: impostor.k.signer,
      keyId: impostor.k.keyId,
    });
    const queriedIssuer = await buildIdentity();
    const isRevoked = createRevocationChecker(
      [A],
      revocationFetch({
        [A]: { [credentialCID]: { revoked: true, revocation: impostorRevocation.jwsToken } },
      }),
      resolveKeyFor(impostor, queriedIssuer),
    );
    expect(await isRevoked(queriedIssuer.did, credentialCID)).toBe(false);
  });

  it('consults ALL relays — a negative first answer does not short-circuit', async () => {
    const { issuer, credentialCID, revocation } = await setup();
    const isRevoked = createRevocationChecker(
      [A, B],
      revocationFetch({
        [A]: { [credentialCID]: { revoked: false } }, // relay A never saw it
        [B]: { [credentialCID]: { revoked: true, revocation: revocation.jwsToken } },
      }),
      resolveKeyFor(issuer),
    );
    expect(await isRevoked(issuer.did, credentialCID)).toBe(true);
  });

  it('returns false only after the full relay set comes up empty', async () => {
    const { issuer, credentialCID } = await setup();
    const isRevoked = createRevocationChecker(
      [A, B],
      revocationFetch({}), // both 404
      resolveKeyFor(issuer),
    );
    expect(await isRevoked(issuer.did, credentialCID)).toBe(false);
  });

  it('wires end-to-end as the client default (resolveKey through the resolvers)', async () => {
    const { issuer, credential, credentialCID, revocation } = await setup();
    const client = createClient({
      relays: [A],
      peerClient: fakePeerClient({ [A]: { identities: { [issuer.did]: issuer.log } } }),
      fetch: revocationFetch({
        [A]: { [credentialCID]: { revoked: true, revocation: revocation.jwsToken } },
      }),
    });
    const res = await client.credential(credential);
    expect(res.value.revoked).toBe(true);
    expect(res.trust.ok).toBe(false);
  });
});
