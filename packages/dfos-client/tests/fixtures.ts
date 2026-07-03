/*

  TEST FIXTURES

  Real signed chains (via @metalabel/dfos-protocol) plus an in-memory fake
  PeerClient. No live network — the fake serves per-relay logs with the same
  `after`/`limit` cursor contract the HTTP peer client speaks, so the client's
  fan-out, quorum, and verify-forward paths exercise real transport orchestration
  against real signatures.

*/

import {
  decodeMultikey,
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyIdentityChain,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createNewEd25519Keypair,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import type { PeerClient, PeerLogEntry } from '@metalabel/dfos-web-relay/peer-client';

const DOC_CID = 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y';
const DOC_CID_2 = 'bafkreiupdatedocument000000000000000000000000000000000000000';

export const ts = (offset = 0): string => new Date(Date.now() + offset * 60_000).toISOString();

export interface Key {
  keyId: string;
  key: MultikeyPublicKey;
  signer: (msg: Uint8Array) => Promise<Uint8Array>;
}

export const makeKey = (): Key => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
  };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keyId, key, signer };
};

export const cidOf = (jws: string): string => {
  const decoded = decodeJwsUnsafe(jws);
  return typeof decoded?.header.cid === 'string' ? decoded.header.cid : '';
};

export const toEntries = (log: string[]): PeerLogEntry[] =>
  log.map((jws) => ({ cid: cidOf(jws), jwsToken: jws }));

export interface BuiltIdentity {
  did: string;
  kid: string;
  k: Key;
  /** A second auth key present only after a rotation update. */
  rotatedKey?: Key;
  genesisLog: string[];
  log: string[];
  genesisCID: string;
  headCID: string;
}

/** Build an identity: genesis, optionally extended with an auth-key rotation update. */
export const buildIdentity = async (opts?: { rotate?: boolean }): Promise<BuiltIdentity> => {
  const k = makeKey();
  const genesis: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [k.key],
    assertKeys: [k.key],
    controllerKeys: [k.key],
    createdAt: ts(-10),
  };
  const g = await signIdentityOperation({ operation: genesis, signer: k.signer, keyId: k.keyId });
  const verified = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [g.jwsToken] });
  const did = verified.did;
  const genesisLog = [g.jwsToken];
  const log = [g.jwsToken];
  let headCID = g.operationCID;
  let rotatedKey: Key | undefined;

  if (opts?.rotate) {
    const k2 = makeKey();
    rotatedKey = k2;
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: g.operationCID,
      authKeys: [k.key, k2.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(-5),
    };
    const u = await signIdentityOperation({
      operation: update,
      signer: k.signer,
      keyId: k.keyId,
      identityDID: did,
    });
    log.push(u.jwsToken);
    headCID = u.operationCID;
  }

  return {
    did,
    kid: `${did}#${k.keyId}`,
    k,
    genesisLog,
    log,
    genesisCID: g.operationCID,
    headCID,
    ...(rotatedKey ? { rotatedKey } : {}),
  };
};

export interface BuiltContent {
  contentId: string;
  genesisLog: string[];
  log: string[];
  genesisCID: string;
  headCID: string;
}

/** Build a content chain owned by `creator`: create, optionally + update. */
export const buildContent = async (
  creator: BuiltIdentity,
  opts?: { update?: boolean },
): Promise<BuiltContent> => {
  const create: ContentOperation = {
    version: 1,
    type: 'create',
    did: creator.did,
    documentCID: DOC_CID,
    baseDocumentCID: null,
    createdAt: ts(-8),
  };
  const c = await signContentOperation({
    operation: create,
    signer: creator.k.signer,
    kid: creator.kid,
  });
  const genesisLog = [c.jwsToken];
  const log = [c.jwsToken];
  let headCID = c.operationCID;

  if (opts?.update) {
    const update: ContentOperation = {
      version: 1,
      type: 'update',
      did: creator.did,
      previousOperationCID: c.operationCID,
      documentCID: DOC_CID_2,
      baseDocumentCID: null,
      createdAt: ts(-4),
    };
    const u = await signContentOperation({
      operation: update,
      signer: creator.k.signer,
      kid: creator.kid,
    });
    log.push(u.jwsToken);
    headCID = u.operationCID;
  }

  // derive the real contentId via a full verify with a creator-key resolver
  const resolveKey = async (kid: string): Promise<Uint8Array> => {
    if (kid !== creator.kid) throw new Error(`unexpected kid ${kid}`);
    return decodeMultikey(creator.k.key.publicKeyMultibase).keyBytes;
  };
  const verified = await verifyContentChain({ log, resolveKey });
  return { contentId: verified.contentId, genesisLog, log, genesisCID: c.operationCID, headCID };
};

// -----------------------------------------------------------------------------
// fake peer client
// -----------------------------------------------------------------------------

export interface RelayData {
  identities?: Record<string, string[]>; // did -> log
  contents?: Record<string, string[]>; // contentId -> log
  operations?: string[]; // global op log
}

const page = (
  entries: PeerLogEntry[],
  params?: { after?: string; limit?: number },
): { entries: PeerLogEntry[]; cursor: string | null } => {
  const limit = params?.limit ?? 1000;
  let start = 0;
  if (params?.after) {
    const idx = entries.findIndex((e) => e.cid === params.after);
    start = idx >= 0 ? idx + 1 : entries.length;
  }
  const slice = entries.slice(start, start + limit);
  const cursor = slice.length === limit ? (slice[slice.length - 1]?.cid ?? null) : null;
  return { entries: slice, cursor };
};

/**
 * A fake PeerClient over a per-relay-URL data map. A URL absent from the map (or
 * a did/contentId absent from that relay) answers `null` — the unreachable/404
 * signal the client fails over on.
 */
export const fakePeerClient = (byUrl: Record<string, RelayData>): PeerClient => ({
  async getIdentityLog(peerUrl, did, params) {
    const log = byUrl[peerUrl]?.identities?.[did];
    if (!log) return null;
    return page(toEntries(log), params);
  },
  async getContentLog(peerUrl, contentId, params) {
    const log = byUrl[peerUrl]?.contents?.[contentId];
    if (!log) return null;
    return page(toEntries(log), params);
  },
  async getOperationLog(peerUrl, params) {
    const log = byUrl[peerUrl]?.operations;
    if (!log) return null;
    return page(toEntries(log), params);
  },
  async submitOperations() {
    /* read-only client — never called */
  },
});
