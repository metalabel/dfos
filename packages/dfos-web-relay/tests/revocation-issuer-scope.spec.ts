import {
  deriveChainIdentifier,
  encodeEd25519Multikey,
  signIdentityOperation,
  signRevocation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createDFOSCredential,
  decodeDFOSCredentialUnsafe,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { ingestOperations } from '../src/ingest';
import { createRelay } from '../src/relay';
import { MemoryRelayStore } from '../src/store';

/*

  REVOCATION IS ISSUER-SCOPED — INCLUDING THE EVICTION

  CREDENTIALS.md, "Relay Enforcement": the relay's revocation set is keyed by
  (issuerDID, credentialCID), and the scoping "prevents a rogue DID from
  revoking credentials it did not issue".

  The revocation SET has always honored that. Evicting the standing PUBLIC
  credential is the other half, and it used to be keyed on the CID alone — so
  any DID that could sign a well-formed revocation naming someone else's
  credential CID destroyed that grant. The eviction now rides in the commit
  batch as `removePublicCredential: { issuerDID, credentialCID }`, and the store
  enforces the pairing. Permanently: re-presenting the credential
  lands on the duplicate-by-CID branch in ingestPublicCredential before
  addPublicCredential can run, so it never comes back.

  The status route is the third half. Any DID can sign a revocation naming any
  CID, so the unscoped `/revocations/v1/credential/:cid` answer is one
  revocation for the CID, not necessarily the issuer's, and a stranger whose DID
  sorts below the issuer's would mask the real one. `?issuer=` scopes the answer
  to the exact (issuerDID, credentialCID) row.

  Twin coverage lives in the Go relay (revocation_issuer_scope_test.go).

*/

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keyId, key, signer };
};

/** One identity whose single key fills all three roles, proved by self-signing. */
const createIdentity = async () => {
  const controller = makeKey();
  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [controller.key],
    assertKeys: [controller.key],
    controllerKeys: [controller.key],
    createdAt: new Date(Date.now() - 3_600_000).toISOString(),
  };
  const { jwsToken } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, key: controller, jwsToken };
};

const RESOURCE = 'chain:someContentId';

/** A store holding one identity's PUBLIC read grant, plus a second identity. */
const seedPublicGrant = async () => {
  const store = new MemoryRelayStore();
  const issuer = await createIdentity();
  const stranger = await createIdentity();
  await ingestOperations([issuer.jwsToken, stranger.jwsToken], store);

  const credential = await createDFOSCredential({
    issuerDID: issuer.did,
    audienceDID: '*',
    att: [{ resource: RESOURCE, action: 'read' }],
    exp: Math.floor(Date.now() / 1000) + 3600,
    signer: issuer.key.signer,
    keyId: issuer.key.keyId,
    iat: Math.floor(Date.now() / 1000) - 3600,
  });
  const credentialCID = decodeDFOSCredentialUnsafe(credential)!.header.cid;
  const [res] = await ingestOperations([credential], store);
  expect(res!.status).toBe('new');
  expect(await store.getPublicCredentials(RESOURCE)).toEqual([credential]);

  const revokeBy = async (identity: { did: string; key: ReturnType<typeof makeKey> }) => {
    const { jwsToken } = await signRevocation({
      issuerDID: identity.did,
      credentialCID,
      signer: identity.key.signer,
      keyId: identity.key.keyId,
    });
    const [result] = await ingestOperations([jwsToken], store);
    return result!;
  };

  return { store, issuer, stranger, credential, credentialCID, revokeBy };
};

describe('relay store — public-credential eviction is issuer-scoped', () => {
  it('ignores an eviction naming a different issuer, and honors the real one', async () => {
    const c = await seedPublicGrant();

    // The eviction is a MEMBER OF THE COMMIT BATCH, not a standalone store call:
    // a revocation lands as one atomic commit that carries the drop it implies.
    // The store is what enforces the pairing, so this drives it the only way a
    // relay can.
    const evictBy = (issuerDID: string, cid: string) =>
      c.store.commit({
        kind: 'operation',
        operation: { cid, jwsToken: cid, chainType: 'revocation', chainId: issuerDID },
        removePublicCredential: { issuerDID, credentialCID: c.credentialCID },
      });

    await evictBy(c.stranger.did, 'evict-by-stranger');
    expect(await c.store.getPublicCredentials(RESOURCE)).toEqual([c.credential]);

    await evictBy(c.issuer.did, 'evict-by-issuer');
    expect(await c.store.getPublicCredentials(RESOURCE)).toEqual([]);
  });
});

describe('relay ingest — a foreign revocation reaches nothing', () => {
  it('leaves the standing public grant intact', async () => {
    const c = await seedPublicGrant();

    // a perfectly valid revocation — signed by the stranger, under the
    // stranger's own key, naming a credential the stranger never issued
    const res = await c.revokeBy(c.stranger);
    expect(res.status).toBe('new');
    // and it must not report a grant it did not reach
    expect(res.revokedGrant).toBeUndefined();

    expect(await c.store.getPublicCredentials(RESOURCE)).toEqual([c.credential]);
    expect(await c.store.isCredentialRevoked(c.issuer.did, c.credentialCID)).toBe(false);
  });

  it("still evicts on the issuer's own revocation", async () => {
    const c = await seedPublicGrant();

    const res = await c.revokeBy(c.issuer);
    expect(res.status).toBe('new');
    expect(res.revokedGrant).toEqual({ wildcard: false, contentIds: ['someContentId'] });

    expect(await c.store.getPublicCredentials(RESOURCE)).toEqual([]);
    expect(await c.store.isCredentialRevoked(c.issuer.did, c.credentialCID)).toBe(true);
  });
});

describe('revocation status route — ?issuer= scopes the answer', () => {
  /** Both the issuer and the stranger revoke the same credential CID. */
  const seedCollision = async () => {
    const c = await seedPublicGrant();
    const signRevocationBy = async (identity: { did: string; key: ReturnType<typeof makeKey> }) =>
      (
        await signRevocation({
          issuerDID: identity.did,
          credentialCID: c.credentialCID,
          signer: identity.key.signer,
          keyId: identity.key.keyId,
        })
      ).jwsToken;
    const issuerRevocation = await signRevocationBy(c.issuer);
    const strangerRevocation = await signRevocationBy(c.stranger);
    const results = await ingestOperations([issuerRevocation, strangerRevocation], c.store);
    expect(results.map((r) => r.status)).toEqual(['new', 'new']);

    const relay = await createRelay({ store: c.store });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const get = async (path: string): Promise<{ status: number; body: any }> => {
      const res = await relay.app.request(`http://localhost${path}`);
      return { status: res.status, body: await res.json() };
    };
    const path = `/revocations/v1/credential/${c.credentialCID}`;
    return { ...c, issuerRevocation, strangerRevocation, get, path };
  };

  it("answers each issuer's own revocation when scoped", async () => {
    const c = await seedCollision();

    for (const [did, revocation] of [
      [c.issuer.did, c.issuerRevocation],
      [c.stranger.did, c.strangerRevocation],
    ] as const) {
      const res = await c.get(`${c.path}?issuer=${encodeURIComponent(did)}`);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ credentialCID: c.credentialCID, revoked: true, revocation });
    }
  });

  it('leaves the unscoped answer unchanged: smallest issuerDID', async () => {
    const c = await seedCollision();
    const smallest = c.issuer.did < c.stranger.did ? c.issuerRevocation : c.strangerRevocation;

    const res = await c.get(c.path);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      credentialCID: c.credentialCID,
      revoked: true,
      revocation: smallest,
    });
  });

  it('answers revoked:false for an issuer with no revocation, whatever others hold', async () => {
    const c = await seedCollision();
    const bystander = await createIdentity();

    const res = await c.get(`${c.path}?issuer=${encodeURIComponent(bystander.did)}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ credentialCID: c.credentialCID, revoked: false });
  });

  it('rejects a present issuer that is not a canonical did:dfos', async () => {
    const c = await seedCollision();

    for (const issuer of ['', 'not-a-did', 'did:dfos:tooshort', `${c.issuer.did}x`]) {
      const res = await c.get(`${c.path}?issuer=${encodeURIComponent(issuer)}`);
      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'invalid DID' });
    }
  });
});
