import { describe, expect, it } from 'vitest';
import {
  encodeEd25519Multikey,
  signContentOperation,
  verifyContentChain,
  verifyContentExtensionFromTrustedState,
} from '../src/chain';
import type { ContentOperation, VerifiedIdentity } from '../src/chain';
import { createDFOSCredential, decodeDFOSCredentialUnsafe } from '../src/credentials';
import type { RevocationChecker } from '../src/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

/*

  AS-OF REVOCATION — acceptance vs validity

  Acceptance is a freshness decision; verification of committed history is a
  validity decision. A timeless `isRevoked` conflates the two: it makes revoking a
  credential today retroactively invalidate every operation it ever authorized,
  which contradicts CREDENTIALS.md "Revocation Scope" ("does not retroactively
  invalidate operations already committed to the content chain").

  These tests pin the fold side of that split: the verifier calls `isRevoked` with
  `asOfUnix` = the operation's OWN `createdAt`, at the leaf AND at every parent
  hop, in both the full-fold and the extension-from-trusted-state path. The
  freshness side (relay ingest still refusing a NEW op under a
  currently-revoked credential) is pinned in the relay suites.

*/

// -----------------------------------------------------------------------------
// fixtures — mirrors the `delegated content chain` block in chain.spec.ts
// -----------------------------------------------------------------------------

const makeIdentity = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const did = `did:dfos:${generateId('test').substring(5)}`;
  const kid = `${did}#${keyId}`;
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
  return { keypair, keyId, did, kid, signer, identity };
};

const ts = (offsetMinutes = 0) => new Date(Date.now() + offsetMinutes * 60_000).toISOString();
const unix = (offsetMinutes = 0) => Math.floor(Date.now() / 1000) + offsetMinutes * 60;
const makeDocCID = async (content: object) =>
  (await dagCborCanonicalEncode(content)).cid.toString();

/**
 * The as-of rule under test, as a store would implement it: a revocation counts
 * only when its own signed `createdAt` is at or before the queried instant.
 * `revokedAtUnix` stands in for the persisted revocation timestamp.
 */
const asOfChecker = (revoked: Map<string, number>): RevocationChecker => {
  return async (issuerDID, credentialCID, asOfUnix) => {
    const revokedAt = revoked.get(`${issuerDID}::${credentialCID}`);
    if (revokedAt === undefined) return false;
    if (asOfUnix === undefined) return true;
    return revokedAt <= asOfUnix;
  };
};

/** The pre-change behavior: a revocation is a timeless boolean. */
const timelessChecker = (revoked: Map<string, number>): RevocationChecker => {
  return async (issuerDID, credentialCID) => revoked.has(`${issuerDID}::${credentialCID}`);
};

/**
 * Build a two-op chain: a creator's genesis plus a delegated update signed by a
 * delegate under an inline write credential. `depth: 2` inserts an intermediate
 * delegate so the PARENT hop of the delegation walk is exercised too.
 *
 * `genesisOffset` / `opOffset` (minutes from now) place the chain in time. Dating
 * the operation in the PAST is what makes a wall-clock substitution detectable: a
 * revocation timestamped between the op and now is invisible to the correct as-of
 * basis but bites under `now`.
 */
const buildDelegatedChain = async (opts?: {
  depth?: 1 | 2;
  genesisOffset?: number;
  opOffset?: number;
}) => {
  const genesisOffset = opts?.genesisOffset ?? 0;
  const opOffset = opts?.opOffset ?? 1;
  const creator = makeIdentity();
  const delegate = makeIdentity();
  const middle = makeIdentity();

  const keys = new Map<string, Uint8Array>([[creator.kid, creator.keypair.publicKey]]);
  const identities = new Map<string, VerifiedIdentity>([[creator.did, creator.identity]]);
  for (const id of [delegate, middle]) {
    keys.set(id.kid, id.keypair.publicKey);
    identities.set(id.did, id.identity);
  }
  const resolveKey = async (kid: string) => {
    const key = keys.get(kid);
    if (!key) throw new Error(`unknown kid: ${kid}`);
    return key;
  };
  const resolveIdentity = async (did: string) => identities.get(did);

  // genesis
  const createOp: ContentOperation = {
    version: 1,
    type: 'create',
    did: creator.did,
    documentCID: await makeDocCID({ type: 'post', title: 'genesis' }),
    baseDocumentCID: null,
    createdAt: ts(genesisOffset),
  };
  const { jwsToken: createJws, operationCID: createCID } = await signContentOperation({
    operation: createOp,
    signer: creator.signer,
    kid: creator.kid,
  });
  const genesis = await verifyContentChain({ log: [createJws], resolveKey });

  // Credential(s): creator → [middle →] delegate. The [iat, exp) window spans
  // hours, not minutes, so it comfortably contains every op placement the fixtures
  // use — a window that merely touched the op's createdAt would flake on a
  // one-second clock tick between the two calls. The window is computed ONCE and
  // shared by every credential in the chain for the same reason: a child whose
  // exp is recomputed a tick after its parent's exceeds it by a second, and the
  // delegation rule (child exp ≤ parent exp) rejects the chain.
  const credIat = unix(-240);
  const credExp = unix(240);
  const att = [{ resource: `chain:${genesis.contentId}`, action: 'write' }];
  let leaf: string;
  let parent: string | undefined;
  if (opts?.depth === 2) {
    parent = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: middle.did,
      att,
      exp: credExp,
      signer: creator.signer,
      keyId: creator.keyId,
      iat: credIat,
    });
    leaf = await createDFOSCredential({
      issuerDID: middle.did,
      audienceDID: delegate.did,
      att,
      prf: [parent],
      exp: credExp,
      signer: middle.signer,
      keyId: middle.keyId,
      iat: credIat,
    });
  } else {
    leaf = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att,
      exp: credExp,
      signer: creator.signer,
      keyId: creator.keyId,
      iat: credIat,
    });
  }

  // delegated update
  const opCreatedAt = ts(opOffset);
  const updateOp: ContentOperation = {
    version: 1,
    type: 'update',
    did: delegate.did,
    previousOperationCID: createCID,
    documentCID: await makeDocCID({ type: 'post', title: 'delegated edit' }),
    baseDocumentCID: null,
    createdAt: opCreatedAt,
    authorization: leaf,
  };
  const { jwsToken: updateJws } = await signContentOperation({
    operation: updateOp,
    signer: delegate.signer,
    kid: delegate.kid,
  });

  return {
    creator,
    middle,
    delegate,
    resolveKey,
    resolveIdentity,
    log: [createJws, updateJws],
    genesis,
    createJws,
    updateJws,
    opCreatedAt,
    opCreatedAtUnix: Math.floor(new Date(opCreatedAt).getTime() / 1000),
    leafKey: `${opts?.depth === 2 ? middle.did : creator.did}::${decodeDFOSCredentialUnsafe(leaf)!.header.cid}`,
    parentKey: parent
      ? `${creator.did}::${decodeDFOSCredentialUnsafe(parent)!.header.cid}`
      : undefined,
  };
};

// -----------------------------------------------------------------------------
// full fold — the healed case
// -----------------------------------------------------------------------------

describe('as-of revocation — cold full fold', () => {
  it('VERIFIES a committed delegated op whose credential was revoked AFTER it', async () => {
    const c = await buildDelegatedChain();
    // revoked 10 minutes from now — strictly after the op's createdAt (+1 min)
    const revoked = new Map([[c.leafKey, unix(10)]]);

    const result = await verifyContentChain({
      log: c.log,
      resolveKey: c.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: c.resolveIdentity,
      isRevoked: asOfChecker(revoked),
    });

    expect(result.length).toBe(2);
    expect(result.headCID).not.toBe(c.genesis.headCID);
  });

  it('REJECTS when the revocation predates the op', async () => {
    const c = await buildDelegatedChain();
    const revoked = new Map([[c.leafKey, unix(-10)]]);

    await expect(
      verifyContentChain({
        log: c.log,
        resolveKey: c.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: c.resolveIdentity,
        isRevoked: asOfChecker(revoked),
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('REJECTS when the revocation lands exactly at the op createdAt (boundary is inclusive)', async () => {
    const c = await buildDelegatedChain();
    const revoked = new Map([[c.leafKey, c.opCreatedAtUnix]]);

    await expect(
      verifyContentChain({
        log: c.log,
        resolveKey: c.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: c.resolveIdentity,
        isRevoked: asOfChecker(revoked),
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('preserves timeless behavior for a checker that ignores asOfUnix', async () => {
    const c = await buildDelegatedChain();
    // same later-revocation fixture as the healed case above — a timeless checker
    // still rejects it, which is exactly the pre-change behavior
    const revoked = new Map([[c.leafKey, unix(10)]]);

    await expect(
      verifyContentChain({
        log: c.log,
        resolveKey: c.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: c.resolveIdentity,
        isRevoked: timelessChecker(revoked),
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('passes the op createdAt (not wall-clock now) as the as-of basis', async () => {
    const c = await buildDelegatedChain();
    const seen: (number | undefined)[] = [];
    const spy: RevocationChecker = async (_issuer, _cid, asOfUnix) => {
      seen.push(asOfUnix);
      return false;
    };

    await verifyContentChain({
      log: c.log,
      resolveKey: c.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: c.resolveIdentity,
      isRevoked: spy,
    });

    expect(seen.length).toBeGreaterThan(0);
    for (const asOf of seen) expect(asOf).toBe(c.opCreatedAtUnix);
  });
});

// -----------------------------------------------------------------------------
// parent hops
// -----------------------------------------------------------------------------

describe('as-of revocation — delegation parents', () => {
  it('VERIFIES when a PARENT credential was revoked after the op', async () => {
    const c = await buildDelegatedChain({ depth: 2 });
    const revoked = new Map([[c.parentKey!, unix(10)]]);

    const result = await verifyContentChain({
      log: c.log,
      resolveKey: c.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: c.resolveIdentity,
      isRevoked: asOfChecker(revoked),
    });

    expect(result.length).toBe(2);
  });

  it('REJECTS when a PARENT credential was already revoked at the op', async () => {
    const c = await buildDelegatedChain({ depth: 2 });
    const revoked = new Map([[c.parentKey!, unix(-10)]]);

    await expect(
      verifyContentChain({
        log: c.log,
        resolveKey: c.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: c.resolveIdentity,
        isRevoked: asOfChecker(revoked),
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('uses the op createdAt (not wall-clock now) as the PARENT hop basis', async () => {
    // The discriminating fixture: the op is dated in the PAST and the parent's
    // revocation lands BETWEEN the op and now. Correct as-of → the parent was live
    // when the op was signed → VERIFIES. Substitute wall-clock `now` for the basis
    // and the same revocation bites → REJECTS. Without this shape, a parent-hop
    // test passes either way and pins nothing.
    const c = await buildDelegatedChain({ depth: 2, genesisOffset: -20, opOffset: -10 });
    const revoked = new Map([[c.parentKey!, unix(-5)]]);

    const result = await verifyContentChain({
      log: c.log,
      resolveKey: c.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: c.resolveIdentity,
      isRevoked: asOfChecker(revoked),
    });
    expect(result.length).toBe(2);

    // same fixture, same revocation, wall-clock basis → the verdict flips
    const wallClockChecker: RevocationChecker = async (issuerDID, credentialCID) =>
      asOfChecker(revoked)(issuerDID, credentialCID, Math.floor(Date.now() / 1000));
    await expect(
      verifyContentChain({
        log: c.log,
        resolveKey: c.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: c.resolveIdentity,
        isRevoked: wallClockChecker,
      }),
    ).rejects.toThrow(/revoked/);
  });

  it('passes the op createdAt to EVERY hop, leaf and parent alike', async () => {
    // The depth-1 spy above only observes the leaf call (a prf:[] credential
    // terminates the walk before any parent check). Depth 2 observes both.
    const c = await buildDelegatedChain({ depth: 2, genesisOffset: -20, opOffset: -10 });
    const seen: (number | undefined)[] = [];
    const spy: RevocationChecker = async (_issuer, _cid, asOfUnix) => {
      seen.push(asOfUnix);
      return false;
    };

    await verifyContentChain({
      log: c.log,
      resolveKey: c.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: c.resolveIdentity,
      isRevoked: spy,
    });

    // leaf + one parent hop
    expect(seen.length).toBe(2);
    for (const asOf of seen) expect(asOf).toBe(c.opCreatedAtUnix);
  });
});

// -----------------------------------------------------------------------------
// extension from trusted state
// -----------------------------------------------------------------------------

describe('as-of revocation — extension from trusted state', () => {
  const extend = (
    c: Awaited<ReturnType<typeof buildDelegatedChain>>,
    isRevoked: RevocationChecker,
  ) =>
    verifyContentExtensionFromTrustedState({
      currentState: c.genesis,
      lastCreatedAt: ts(0),
      newOp: c.updateJws,
      resolveKey: c.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: c.resolveIdentity,
      isRevoked,
    });

  it('VERIFIES an extension whose credential was revoked after the op', async () => {
    const c = await buildDelegatedChain();
    const result = await extend(c, asOfChecker(new Map([[c.leafKey, unix(10)]])));
    expect(result.state.length).toBe(2);
  });

  it('REJECTS an extension whose credential was already revoked at the op', async () => {
    const c = await buildDelegatedChain();
    await expect(extend(c, asOfChecker(new Map([[c.leafKey, unix(-10)]])))).rejects.toThrow(
      /revoked/,
    );
  });
});
