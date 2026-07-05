/*

  PHASE 2 — resolve public projections

  Phase 1 (sync.ts) lands op rows + head rollups: cheap, no blobs. It cannot
  answer "what is this content chain's type?" or "what is this identity's name?"
  — those live in the relay-gated content-plane blob, not the op log.

  Phase 2 materializes exactly those browse fields, at the cost the HANDOFF named:
  ONE blob fetch per public content chain. For each content rollup we have not
  resolved at its current head:

    1. read the head op from the LOCAL index, re-derive its self-CID (house idiom),
       and take the committed documentCID it signs;
    2. fetch the blob once (fans across relays) and re-hash the served bytes to that
       committed CID — the identity.tsx integrity gate — before trusting anything;
    3. on a match, record docSchema + publicRead; a profile/v1 doc is additionally
       ATTRIBUTED to an identity via the cheap creator-heuristic (decision B):
       the content chain's genesis-op signer kid → DID. "attributed", not "verified"
       — author == subject by convention; the identity detail page is the proof.

  Resumable: a rollup whose `resolvedHead` already equals its `headCid` is skipped,
  so re-runs only touch chains whose head drifted. Abortable via `signal`. This is
  the "rich requires-full-download UX" — paid once per head, then browse is instant.

  Chains resolve through a bounded worker pool: each chain is independent (one
  fetch, one rollup write), so the network waits overlap. The one shared surface
  is the ATTRIBUTION write — two content chains can attribute the same identity
  DID, and its read-modify-write would lose updates under interleaving — so those
  writes alone are serialized through a mutex.

  The blob fetch is PREFILTERED by the standing public-read grant set folded from
  local credential + revocation ops (public-grants.ts): a chain with no standing
  grant is stamped gated straight from the log — no fetch, no guaranteed-401.
  A chain whose stored publicness DISAGREES with the grant fold (a grant issued
  or revoked since) is re-resolved even without head drift.

*/

import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { ChainRollup, ExplorerDb, ExplorerOp } from './db';
import { didOfKid } from './format';
import { parseMediaObject } from './media';
import { isProfileContent } from './profile';
import { isFetchEligible, publicGrantSet } from './public-grants';
import { fetchBlobRaw, type BlobResult } from './relay-raw';

export interface ProjectionProgress {
  /** content chains processed this run (resolved to public / gated / cleared). */
  resolved: number;
  /** of those, resolved to a public integrity-checked document. */
  publicDocs: number;
  /** profiles attributed to an identity rollup this run. */
  attributed: number;
  /** content chains eligible this run (unresolved or head-drifted). */
  total: number;
}

export interface ResolveOptions {
  db: ExplorerDb;
  relays: string[];
  /** Injectable for tests; defaults to the real content-plane blob fetch. */
  fetchBlob?: (contentId: string, relays: string[]) => Promise<BlobResult>;
  onProgress?: (p: ProjectionProgress) => void;
  signal?: AbortSignal;
}

/** The DID that authored a content op — its signer kid, falling back to payload.did. */
const creatorDid = (kid: string, payload: Record<string, unknown>): string => {
  const fromKid = didOfKid(kid);
  if (fromKid) return fromKid;
  return typeof payload['did'] === 'string' ? (payload['did'] as string) : '';
};

interface OneResult {
  /** the head this outcome pins to — stamped on the rollup so we resolve once. */
  resolvedHead: string;
  publicRead: boolean;
  docSchema?: string;
  /** the chain's genesis signer, when derivable — the DID a profile attributes to
   *  (present on BOTH the public and gated paths so a drift can clear a stale name). */
  attributedDid?: string;
  /** set only when the resolved public doc is a profile/v1 (→ write attribution). */
  profileName?: string;
  avatarRef?: string;
}

/** decoded op payload paired with its row — decode each JWS once per chain. */
interface DecodedOp {
  op: ExplorerOp;
  payload: Record<string, unknown>;
}

const encodeCid = async (value: Record<string, unknown>): Promise<string | null> => {
  try {
    return (await dagCborCanonicalEncode(value)).cid.toString();
  } catch {
    return null;
  }
};

/** Resolve a single content chain's projection. Returns null when even the head
 *  op is unreadable (leave it unresolved to retry on a later run). */
const resolveOne = async (
  db: ExplorerDb,
  rollup: ChainRollup,
  relays: string[],
  fetchBlob: (contentId: string, relays: string[]) => Promise<BlobResult>,
  fetchEligible: boolean,
): Promise<OneResult | null> => {
  const ops = await db.chainOps(rollup.chainId, 'content-op');
  if (ops.length === 0) return null;
  // decode each op's payload once and reuse (head self-CID + genesis detection)
  const decoded: DecodedOp[] = ops.map((op) => ({
    op,
    payload: decodeJwsUnsafe(op.jwsToken)?.payload ?? {},
  }));
  const head = decoded.find((d) => d.op.cid === rollup.headCid) ?? decoded[decoded.length - 1];
  if (!head) return null;

  // the genesis signer attributes any profile on this chain — derived on EVERY
  // path (public or not) so a drift to gated/deleted can clear a stale name.
  const genesis = decoded.find((d) => !d.payload['previousOperationCID']) ?? decoded[0];
  const attributedDid = genesis ? creatorDid(genesis.op.kid, genesis.payload) : '';
  const withDid = (r: Omit<OneResult, 'attributedDid'>): OneResult =>
    attributedDid ? { ...r, attributedDid } : r;

  const committedDocCid =
    typeof head.payload['documentCID'] === 'string'
      ? (head.payload['documentCID'] as string)
      : null;

  // the committed doc CID must come from an op whose bytes actually hash to its
  // own CID — not a relay-fabricated {cid, payload} pair. Also covers a deleted
  // head (documentCID cleared → no public doc).
  const selfCid = await encodeCid(head.payload);
  if (selfCid !== head.op.cid || !committedDocCid) {
    return withDid({ resolvedHead: head.op.cid, publicRead: false });
  }

  // no standing public grant in the log → an anonymous fetch is denied by
  // construction; stamp gated straight from the math (no network round-trip)
  if (!fetchEligible) {
    return withDid({ resolvedHead: head.op.cid, publicRead: false });
  }

  const blob = await fetchBlob(rollup.chainId, relays);
  if (!blob.bytes) return withDid({ resolvedHead: head.op.cid, publicRead: false }); // gated / absent

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: false }).decode(blob.bytes));
  } catch {
    return withDid({ resolvedHead: head.op.cid, publicRead: false }); // not a JSON document
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return withDid({ resolvedHead: head.op.cid, publicRead: false });
  }
  const derived = await encodeCid(parsed as Record<string, unknown>);
  if (derived !== committedDocCid) {
    return withDid({ resolvedHead: head.op.cid, publicRead: false }); // served bytes ≠ committed CID
  }

  const rec = parsed as Record<string, unknown>;
  const docSchema = typeof rec['$schema'] === 'string' ? rec['$schema'] : undefined;
  const out: OneResult = withDid({
    resolvedHead: head.op.cid,
    publicRead: true,
    ...(docSchema ? { docSchema } : {}),
  });

  // profile/v1 → attribute to the genesis signer (cheap creator-heuristic)
  if (isProfileContent(parsed)) {
    const name = typeof parsed.name === 'string' ? parsed.name.trim() : '';
    if (attributedDid && name) {
      out.profileName = name;
      const avatarRef = parseMediaObject(parsed.avatar)?.uri;
      if (avatarRef) out.avatarRef = avatarRef;
    }
  }
  return out;
};

/** Merge a content chain's resolved projection onto its rollup (clears stale
 *  docSchema when a head-drift made a once-public chain gated). */
const writeContentProjection = async (
  db: ExplorerDb,
  chainId: string,
  r: OneResult,
): Promise<void> => {
  const existing = await db.getChain(chainId);
  if (!existing) return;
  const merged: ChainRollup = {
    ...existing,
    resolvedHead: r.resolvedHead,
    publicRead: r.publicRead,
  };
  if (r.docSchema) merged.docSchema = r.docSchema;
  else delete merged.docSchema;
  await db.putBatch([], [merged]);
};

/** Patch the attributed identity rollup with the profile name/avatar — only if
 *  that identity is itself in the index (never fabricate a phantom rollup). The
 *  source content chain is recorded so a later drift can clear a stale name. */
const writeAttribution = async (
  db: ExplorerDb,
  did: string,
  sourceContentId: string,
  name: string,
  avatarRef: string | undefined,
): Promise<boolean> => {
  const idRollup = await db.getChain(did);
  if (!idRollup || idRollup.kind !== 'identity-op') return false;
  const merged: ChainRollup = {
    ...idRollup,
    name,
    nameLower: name.toLowerCase(),
    publicRead: true,
    profileSource: sourceContentId,
  };
  if (avatarRef) merged.avatarRef = avatarRef;
  else delete merged.avatarRef;
  await db.putBatch([], [merged]);
  return true;
};

/** Clear a stale attribution when the profile chain that set it is no longer a
 *  public profile — but ONLY if THIS chain is the recorded source (another
 *  chain may since have attributed a different name to the same DID). */
const clearAttribution = async (
  db: ExplorerDb,
  did: string,
  sourceContentId: string,
): Promise<void> => {
  const idRollup = await db.getChain(did);
  if (!idRollup || idRollup.profileSource !== sourceContentId) return;
  const merged: ChainRollup = { ...idRollup, publicRead: false };
  delete merged.name;
  delete merged.nameLower;
  delete merged.avatarRef;
  delete merged.profileSource;
  await db.putBatch([], [merged]);
};

/** In-flight resolves at once. Each is one blob fetch + a hash — network-bound,
 *  so overlapping them is nearly free; bounded to stay polite to relays. */
const CONCURRENCY = 8;

/**
 * Resolve every unresolved (or head-drifted) public content chain's projection.
 * Bounded-parallel and abortable; persists per chain so a stop/refresh resumes
 * cleanly (workers finish their in-flight chain and stop picking up new ones).
 */
export const resolvePublicProjections = async (
  opts: ResolveOptions,
): Promise<{ resolved: number; publicDocs: number; attributed: number }> => {
  const { db, relays, signal, onProgress } = opts;
  const fetchBlob = opts.fetchBlob ?? fetchBlobRaw;

  // fold the standing public-read grant set once per run (public-grants.ts)
  const [credentialOps, revocationOps] = await Promise.all([
    db.opsOfKind('credential', 100000),
    db.opsOfKind('revocation', 100000),
  ]);
  const grants = publicGrantSet(credentialOps, revocationOps, Math.floor(Date.now() / 1000));

  // eligible: head drifted since last resolve, OR the grant fold disagrees with
  // the stored publicness (a grant was issued or revoked under an unmoved head)
  const content = (await db.allChains()).filter(
    (c) =>
      c.kind === 'content-op' &&
      (c.resolvedHead !== c.headCid ||
        isFetchEligible(grants, c.chainId) !== (c.publicRead === true)),
  );
  const total = content.length;

  let resolved = 0;
  let publicDocs = 0;
  let attributed = 0;

  // identity-rollup attribution is a read-modify-write over a SHARED row (two
  // chains can attribute the same DID) — serialize just those writes.
  let attributionLock: Promise<unknown> = Promise.resolve();
  const withAttributionLock = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = attributionLock.then(fn, fn);
    attributionLock = run.catch(() => undefined);
    return run;
  };

  let next = 0;
  const worker = async (): Promise<void> => {
    while (!signal?.aborted) {
      const i = next;
      next += 1;
      if (i >= content.length) return;
      const rollup = content[i]!;
      const result = await resolveOne(
        db,
        rollup,
        relays,
        fetchBlob,
        isFetchEligible(grants, rollup.chainId),
      );
      if (!result) continue;

      await writeContentProjection(db, rollup.chainId, result);
      resolved += 1;
      if (result.publicRead) publicDocs += 1;

      // attribute a public profile to its genesis signer; on any other outcome,
      // clear a stale name this chain previously set (deleted / gated / retyped)
      const { attributedDid, profileName, avatarRef } = result;
      if (attributedDid) {
        if (profileName) {
          const ok = await withAttributionLock(() =>
            writeAttribution(db, attributedDid, rollup.chainId, profileName, avatarRef),
          );
          if (ok) attributed += 1;
        } else {
          await withAttributionLock(() => clearAttribution(db, attributedDid, rollup.chainId));
        }
      }

      onProgress?.({ resolved, publicDocs, attributed, total });
    }
  };

  const pool = Math.min(CONCURRENCY, content.length);
  await Promise.all(Array.from({ length: pool }, () => worker()));

  return { resolved, publicDocs, attributed };
};
