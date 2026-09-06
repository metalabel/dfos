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
import { MemoryRelayStore } from '../src/store';

/*

  REVOCATION IS ISSUER-SCOPED — INCLUDING THE EVICTION

  CREDENTIALS.md, "Relay Enforcement": the relay's revocation set is keyed by
  (issuerDID, credentialCID), and the scoping "prevents a rogue DID from
  revoking credentials it did not issue".

  The revocation SET has always honored that. Evicting the standing PUBLIC
  credential is the other half, and it used to be keyed on the CID alone — so
  any DID that could sign a well-formed revocation naming someone else's
  credential CID destroyed that grant. Permanently: re-presenting the credential
  lands on the duplicate-by-CID branch in ingestPublicCredential before
  addPublicCredential can run, so it never comes back.

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

    await c.store.removePublicCredential(c.stranger.did, c.credentialCID);
    expect(await c.store.getPublicCredentials(RESOURCE)).toEqual([c.credential]);

    await c.store.removePublicCredential(c.issuer.did, c.credentialCID);
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
