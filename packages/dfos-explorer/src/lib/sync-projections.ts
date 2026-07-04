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

*/

import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { ChainRollup, ExplorerDb, ExplorerOp } from './db';
import { parseMediaObject } from './media';
import { isProfileContent } from './profile';
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

/** kid (`did:dfos:xxx#key`) → the DID prefix, '' when there is no fragment. */
const didOfKid = (kid: string): string => {
  const i = kid.indexOf('#');
  return i > 0 ? kid.slice(0, i) : '';
};

/** The DID that authored a content op — its signer kid, falling back to payload.did. */
const creatorDidOf = (op: ExplorerOp): string => {
  const fromKid = didOfKid(op.kid);
  if (fromKid) return fromKid;
  const decoded = decodeJwsUnsafe(op.jwsToken);
  return typeof decoded?.payload['did'] === 'string' ? (decoded.payload['did'] as string) : '';
};

interface OneResult {
  /** the head this outcome pins to — stamped on the rollup so we resolve once. */
  resolvedHead: string;
  publicRead: boolean;
  docSchema?: string;
  attribution?: { did: string; name: string; avatarRef?: string };
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
): Promise<OneResult | null> => {
  const ops = await db.chainOps(rollup.chainId, 'content-op');
  if (ops.length === 0) return null;
  const headOp = ops.find((o) => o.cid === rollup.headCid) ?? ops[ops.length - 1];
  if (!headOp) return null;

  const headDecoded = decodeJwsUnsafe(headOp.jwsToken);
  const committedDocCid =
    typeof headDecoded?.payload['documentCID'] === 'string'
      ? (headDecoded.payload['documentCID'] as string)
      : null;

  // the committed doc CID must come from an op whose bytes actually hash to its
  // own CID — not a relay-fabricated {cid, payload} pair. Also covers a deleted
  // head (documentCID cleared → no public doc).
  const selfCid = headDecoded ? await encodeCid(headDecoded.payload) : null;
  if (selfCid !== headOp.cid || !committedDocCid) {
    return { resolvedHead: headOp.cid, publicRead: false };
  }

  const blob = await fetchBlob(rollup.chainId, relays);
  if (!blob.bytes) return { resolvedHead: headOp.cid, publicRead: false }; // gated / absent

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: false }).decode(blob.bytes));
  } catch {
    return { resolvedHead: headOp.cid, publicRead: false }; // not a JSON document
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { resolvedHead: headOp.cid, publicRead: false };
  }
  const derived = await encodeCid(parsed as Record<string, unknown>);
  if (derived !== committedDocCid) {
    return { resolvedHead: headOp.cid, publicRead: false }; // served bytes ≠ committed CID
  }

  const rec = parsed as Record<string, unknown>;
  const docSchema = typeof rec['$schema'] === 'string' ? rec['$schema'] : undefined;
  const out: OneResult = {
    resolvedHead: headOp.cid,
    publicRead: true,
    ...(docSchema ? { docSchema } : {}),
  };

  // profile/v1 → attribute to the genesis signer (cheap creator-heuristic)
  if (isProfileContent(parsed)) {
    const genesis =
      ops.find((o) => !decodeJwsUnsafe(o.jwsToken)?.payload['previousOperationCID']) ?? ops[0];
    const did = genesis ? creatorDidOf(genesis) : '';
    const name = typeof parsed.name === 'string' ? parsed.name.trim() : '';
    if (did && name) {
      const avatarRef = parseMediaObject(parsed.avatar)?.uri;
      out.attribution = { did, name, ...(avatarRef ? { avatarRef } : {}) };
    }
  }
  return out;
};

/** Merge a content chain's resolved projection onto its rollup (clears stale
 *  docSchema when a head-drift made a once-public chain gated). */
const writeContentProjection = async (db: ExplorerDb, chainId: string, r: OneResult): Promise<void> => {
  const existing = await db.getChain(chainId);
  if (!existing) return;
  const merged: ChainRollup = { ...existing, resolvedHead: r.resolvedHead, publicRead: r.publicRead };
  if (r.docSchema) merged.docSchema = r.docSchema;
  else delete merged.docSchema;
  await db.putBatch([], [merged]);
};

/** Patch the attributed identity rollup with the profile name/avatar — only if
 *  that identity is itself in the index (never fabricate a phantom rollup). */
const writeAttribution = async (
  db: ExplorerDb,
  attribution: NonNullable<OneResult['attribution']>,
): Promise<boolean> => {
  const idRollup = await db.getChain(attribution.did);
  if (!idRollup || idRollup.kind !== 'identity-op') return false;
  const merged: ChainRollup = {
    ...idRollup,
    name: attribution.name,
    nameLower: attribution.name.toLowerCase(),
    publicRead: true,
  };
  if (attribution.avatarRef) merged.avatarRef = attribution.avatarRef;
  else delete merged.avatarRef;
  await db.putBatch([], [merged]);
  return true;
};

/**
 * Resolve every unresolved (or head-drifted) public content chain's projection.
 * Sequential and abortable; persists per chain so a stop/refresh resumes cleanly.
 */
export const resolvePublicProjections = async (
  opts: ResolveOptions,
): Promise<{ resolved: number; publicDocs: number; attributed: number }> => {
  const { db, relays, signal, onProgress } = opts;
  const fetchBlob = opts.fetchBlob ?? fetchBlobRaw;

  const content = (await db.allChains()).filter(
    (c) => c.kind === 'content-op' && c.resolvedHead !== c.headCid,
  );
  const total = content.length;

  let resolved = 0;
  let publicDocs = 0;
  let attributed = 0;

  for (const rollup of content) {
    if (signal?.aborted) break;
    const result = await resolveOne(db, rollup, relays, fetchBlob);
    if (!result) continue;

    await writeContentProjection(db, rollup.chainId, result);
    resolved += 1;
    if (result.publicRead) publicDocs += 1;
    if (result.attribution && (await writeAttribution(db, result.attribution))) attributed += 1;

    onProgress?.({ resolved, publicDocs, attributed, total });
  }

  return { resolved, publicDocs, attributed };
};
