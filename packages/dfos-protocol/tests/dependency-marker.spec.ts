import { describe, expect, it } from 'vitest';
import {
  encodeEd25519Multikey,
  signContentOperation,
  signCreditClaim,
  verifyContentChain,
  type ContentOperation,
  type VerifiedIdentity,
} from '../src/chain';
import { verifyCreditClaim } from '../src/chain/credit-claim';
import { createDFOSCredential, verifyDFOSCredential } from '../src/credentials';
import { createNewEd25519Keypair, generateId, signPayloadEd25519 } from '../src/crypto';
import { isDependencyMissing } from '../src/dependency';

/*

  THE DEPENDENCY MARKER

  A verification failure caused by the CALLER'S resolver not producing an
  identity or key is not a verdict on the artifact — it is "could not check
  here", and a relay reads it as retryable. These tests pin which failures carry
  the marker and, just as importantly, which do not: over-marking would make a
  real verdict retryable and keep a rejected operation alive forever, which is
  the mirror image of the bug the marker replaced (substring-matching an error
  message whose text the submitter partly writes).

  The Go twin's equivalent is TestResolverErrorSurvivesEveryVerifyEntrypoint in
  dfos-protocol-go, which asserts the same fact through errors.Is.

*/

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  const identity: VerifiedIdentity = {
    did,
    isDeleted: false,
    authKeys: [
      { id: keyId, type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey) },
    ],
    assertKeys: [],
    controllerKeys: [],
    services: [],
  };
  return { keypair, keyId, did, kid: `${did}#${keyId}`, signer, identity };
};

/** An identity that resolves but declares no keys — the "key not on identity" miss. */
const withoutKeys = (identity: VerifiedIdentity): VerifiedIdentity => ({
  ...identity,
  authKeys: [],
  assertKeys: [],
  controllerKeys: [],
});

const futureUnix = (minutes: number) => Math.floor(Date.now() / 1000) + minutes * 60;

const caught = async (run: () => Promise<unknown>): Promise<unknown> => {
  try {
    await run();
  } catch (err) {
    return err;
  }
  throw new Error('expected the verification to fail');
};

const mintCredential = async (issuer: ReturnType<typeof makeIdentity>, audienceDID: string) =>
  createDFOSCredential({
    issuerDID: issuer.did,
    audienceDID,
    att: [{ resource: 'chain:*', action: 'write' }],
    exp: futureUnix(60),
    signer: issuer.signer,
    keyId: issuer.keyId,
  });

describe('dependency marker', () => {
  it('marks a credential whose issuer identity the resolver does not hold', async () => {
    const issuer = makeIdentity();
    const credential = await mintCredential(issuer, '*');
    const err = await caught(() =>
      verifyDFOSCredential(credential, { resolveIdentity: async () => undefined }),
    );
    expect(isDependencyMissing(err)).toBe(true);
  });

  it('marks a credential whose signing key is absent from the resolved identity', async () => {
    const issuer = makeIdentity();
    const credential = await mintCredential(issuer, '*');
    const err = await caught(() =>
      verifyDFOSCredential(credential, {
        resolveIdentity: async () => withoutKeys(issuer.identity),
      }),
    );
    expect(isDependencyMissing(err)).toBe(true);
  });

  it('marks a credit claim whose claimant identity or key the resolver does not hold', async () => {
    const claimant = makeIdentity();
    const contentId = generateId('test').substring(5);
    const { jwsToken } = await signCreditClaim({
      contentId,
      did: claimant.did,
      role: 'author',
      signer: claimant.signer,
      keyId: claimant.keyId,
    });

    const missingIdentity = await caught(() =>
      verifyCreditClaim(jwsToken, {
        expectedContentId: contentId,
        resolveIdentity: async () => undefined,
      }),
    );
    expect(isDependencyMissing(missingIdentity)).toBe(true);

    const missingKey = await caught(() =>
      verifyCreditClaim(jwsToken, {
        expectedContentId: contentId,
        resolveIdentity: async () => withoutKeys(claimant.identity),
      }),
    );
    expect(isDependencyMissing(missingKey)).toBe(true);
  });

  it('does not mark a verdict the resolver already had the evidence to reach', async () => {
    const issuer = makeIdentity();
    const credential = await mintCredential(issuer, '*');

    // A deleted issuer: the resolver produced the identity and its state says
    // no. Re-asking later cannot change that.
    const deleted = await caught(() =>
      verifyDFOSCredential(credential, {
        resolveIdentity: async () => ({ ...issuer.identity, isDeleted: true }),
      }),
    );
    expect(isDependencyMissing(deleted)).toBe(false);

    // A bad signature: the resolver produced the key id the credential names,
    // and the bytes behind it do not verify. A full verdict on the artifact.
    const impostor = createNewEd25519Keypair();
    const forged = await caught(() =>
      verifyDFOSCredential(credential, {
        resolveIdentity: async () => ({
          ...issuer.identity,
          authKeys: [
            {
              id: issuer.keyId,
              type: 'Multikey',
              publicKeyMultibase: encodeEd25519Multikey(impostor.publicKey),
            },
          ],
        }),
      }),
    );
    expect(isDependencyMissing(forged)).toBe(false);
  });

  it('carries the marker across the content-chain authorization re-wrap', async () => {
    // The delegated write path re-throws the credential error with the log index
    // prefixed. That boundary must not eat the marker — a relay classifying the
    // rejection sees only the outer error.
    const creator = makeIdentity();
    const delegate = makeIdentity();
    const genesisOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: creator.did,
      documentCID: 'bafyreiabc',
      baseDocumentCID: null,
      createdAt: new Date().toISOString(),
      note: null,
    };
    const genesis = await signContentOperation({
      operation: genesisOp,
      signer: creator.signer,
      kid: creator.kid,
    });
    const credential = await mintCredential(creator, delegate.did);
    const update = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID: genesis.operationCID,
        documentCID: 'bafyreidef',
        baseDocumentCID: null,
        createdAt: new Date(Date.now() + 60_000).toISOString(),
        note: null,
        authorization: credential,
      },
      signer: delegate.signer,
      kid: delegate.kid,
    });

    const keys = new Map([
      [creator.kid, creator.keypair.publicKey],
      [delegate.kid, delegate.keypair.publicKey],
    ]);
    const err = await caught(() =>
      verifyContentChain({
        log: [genesis.jwsToken, update.jwsToken],
        resolveKey: async (kid: string) => keys.get(kid)!,
        enforceAuthorization: true,
        // The credential's issuer is the creator, and this resolver does not
        // hold it — the miss the marker exists for.
        resolveIdentity: async () => undefined,
      }),
    );
    expect(isDependencyMissing(err)).toBe(true);
  });
});
