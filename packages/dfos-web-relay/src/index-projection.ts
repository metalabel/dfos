/*

  INDEX (v0) — PROJECTION WORKER

  The `/index/v0` family is served from materialized rows. This is the worker
  that maintains them: it walks the global operation log from a persisted
  cursor, maps each entry to the rows it dirties, recomputes those rows through
  the shared builders (index-routes.ts), and applies them in one batch.

  IT IS NOT PART OF INGESTION. Maintenance used to run inside the accepting
  path, and two triggers fan out over a bounded-but-large superset: a `chain:*`
  grant touches every content row, and a revocation the relay could not resolve
  touched every currently-public row. The second was reachable by an anonymous
  POST and free to mint, so an unbounded corpus sweep sat behind an unauthenticated
  request (issue #266). Three things change that:

   1. The projection reads the LOG, not the ingest result, so it runs whenever
      the operator runs it — after a commit, on a timer, or in another process
      entirely. Nothing about it is inside a write transaction.
   2. The unresolvable-revocation trigger is gone. A revocation names a credential
      CID, and the credential's own operation is in the store, so the grant it
      carried is an O(1) lookup: a revocation for a credential this relay never
      held, or one signed by anyone other than that credential's issuer, dirties
      NOTHING instead of sweeping the public corpus.
   3. The remaining fan-outs (a `chain:*` grant, an identity delete or restore)
      are a RESUMABLE SWEEP with a per-run row cap, carried on the same cursor.
      An unbounded stall becomes a bounded one that drains across runs.

  Row VALUES are a pure function of (chain state, held blobs, standing
  credentials), so every recompute converges to the same row regardless of when
  it runs — which is what makes an incremental run and a full rebuild
  interchangeable, and what makes a deferred recompute safe.

  A materialized row is a snapshot of standing authority AT LAST TOUCH. One input
  to `publicRead` — a standing credential's `exp`, and the revocation of a
  credential further up a delegation chain — is not observable from the operation
  that would dirty the row, so a row can advertise `publicRead: true` after the
  grant behind it stopped holding, until the next operation touches that content
  or a rebuild runs. That is the lag the index hint plane already licenses:
  authoritative reads re-verify through `hasPublicStandingAuth` at request time,
  which checks revocation at every delegation level.

*/

import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import {
  artifactIndexRow,
  contentIndexRow,
  creditIndexRows,
  identityIndexRow,
  type IndexOperationRow,
} from './index-routes';
import { resolveSignerKeyMultibase } from './ingest';
import {
  contentIdsFromCredential,
  provedKeyState,
  type IndexCursor,
  type IndexReadStore,
  type IndexRowBatch,
  type IndexSweepState,
  type IndexWriteStore,
  type LogEntry,
  type RelayReadStore,
  type StoredPublicCredential,
} from './types';

/** The store shape the projection worker needs. */
export type IndexProjectionStore = RelayReadStore & IndexReadStore & IndexWriteStore;

/**
 * Log entries projected, and content rows swept, per run. The cap that turns an
 * unbounded corpus sweep into work that drains across runs.
 */
export const DEFAULT_INDEX_PROJECTION_BUDGET = 5000;

export interface IndexProjectionOptions {
  /** Combined per-run cap on swept content rows and projected log entries. */
  budget?: number;
}

export interface IndexProjectionRun {
  /** Log entries projected in this run. */
  projected: number;
  /** Content rows recomputed by the resumable sweep in this run. */
  swept: number;
  /** No sweep outstanding and the log cursor reached the tip. */
  caughtUp: boolean;
}

/**
 * Report an error the projection swallowed.
 *
 * The projection is a non-authoritative hint plane, so it must never fail an
 * authoritative write — but swallowed is not the same as SILENT: a persistently
 * failing projection looks exactly like a quiet one otherwise. One structured
 * line per failure, matching the Go twin's slog call so a single query works
 * across implementations.
 */
export const logIndexProjectionError = (site: string, error: unknown): void => {
  console.warn(
    JSON.stringify({
      event: 'relay.index.projection_failed',
      site,
      reason: error instanceof Error ? error.message : String(error),
    }),
  );
};

// -----------------------------------------------------------------------------
// row accumulation
// -----------------------------------------------------------------------------

/** Everything one run recomputed, applied in a single `applyIndexRows`. */
interface RunRows extends Required<IndexRowBatch> {}

const emptyRows = (): RunRows => ({
  identities: [],
  content: [],
  credits: [],
  artifacts: [],
  countersignatures: [],
  operations: [],
  operationSignerKeys: [],
  identityKeys: [],
  contentSigners: [],
});

/** Content ids and DIDs whose rows this run must recompute. */
interface DirtySet {
  contentIds: Set<string>;
  identityDIDs: Set<string>;
}

// -----------------------------------------------------------------------------
// credential scope
// -----------------------------------------------------------------------------

const contentIdsFromCredentialToken = (
  jwsToken: string,
): { wildcard: boolean; contentIds: string[] } => {
  const decoded = decodeJwsUnsafe(jwsToken);
  const att = (decoded?.payload as Record<string, unknown> | undefined)?.['att'];
  const credential = {
    att: Array.isArray(att)
      ? att.filter(
          (entry): entry is StoredPublicCredential['att'][number] =>
            typeof (entry as Record<string, unknown> | null)?.['resource'] === 'string',
        )
      : [],
  };
  return contentIdsFromCredential(credential);
};

/**
 * Every public key an identity chain has EVER PROVED, across all three key
 * classes — the material behind the has-ever-proved `key=` reverse index.
 *
 * PROVED, NOT DECLARED, AND THE DIFFERENCE IS THE WHOLE POINT. This index is the
 * one-key-one-DID oracle a holder consults before signing a key proof, and it
 * refuses when some chain already proved the key, because proving one key into
 * two chains publishes an irreversible public link between them. A DECLARATION
 * publishes no such link — anyone can write anyone's public key into their own
 * chain — so an index of declarations would let a stranger BURN a key they do
 * not hold, by writing it into a chain and making every future ceremony refuse
 * it.
 *
 * Read from the chain's CURRENT state rather than from the operation's own
 * arrays: an operation's arrays are declarations, and whether a declaration is
 * proved is a verdict of the chain walk. `provedKeys` is monotonic and the rows
 * are append-only, so writing the current union while projecting any of the
 * chain's operations converges on the same table.
 */
const provedKeys = (state: VerifiedIdentity): { publicKeyMultibase: string; id: string }[] => {
  const proved = provedKeyState(state);
  // stored VERBATIM — the filter is an opaque byte match, so nothing here
  // normalizes, validates, or re-encodes the multibase string
  return [...proved.authKeys, ...proved.assertKeys, ...proved.controllerKeys].map((key) => ({
    publicKeyMultibase: key.publicKeyMultibase,
    id: key.id,
  }));
};

// -----------------------------------------------------------------------------
// row recompute
// -----------------------------------------------------------------------------

const recomputeIdentityRow = async (
  did: string,
  store: RelayReadStore,
  rows: RunRows,
): Promise<void> => {
  const chain = await store.getIdentityChain(did);
  if (!chain) return;
  rows.identities.push(await identityIndexRow(chain, store));
};

/**
 * Recompute one content row and its credit rows, then mark every identity row
 * anchored on it dirty — an identity's profile projection embeds the anchored
 * content's publicRead, doc schema, and name, so a content change is also an
 * identity change.
 */
const recomputeContentRow = async (
  contentId: string,
  store: RelayReadStore & IndexReadStore,
  rows: RunRows,
  dirty: DirtySet,
): Promise<void> => {
  const chain = await store.getContentChain(contentId);
  if (!chain) return;
  rows.content.push(await contentIndexRow(chain, store));
  rows.credits.push({ contentId, rows: await creditIndexRows(chain, store) });
  for (const did of await store.getIndexIdentityDIDsByProfileAnchor(contentId)) {
    dirty.identityDIDs.add(did);
  }
};

// -----------------------------------------------------------------------------
// sweep
// -----------------------------------------------------------------------------

/**
 * Widen an outstanding sweep by a newly triggered one. Any new trigger restarts
 * from the beginning: it reaches rows an in-progress sweep has already passed.
 * `all` absorbs `public`.
 */
const widenSweep = (
  current: IndexSweepState | null,
  incoming: IndexSweepState,
): IndexSweepState => ({
  scope: current?.scope === 'all' || incoming.scope === 'all' ? 'all' : 'public',
  after: null,
});

/**
 * Advance a resumable sweep by at most `cap` content rows, marking each one
 * dirty. Returns the sweep state to persist — `null` once the corpus is drained.
 *
 * The `public` scope enumerates only currently-public-read rows, which is the
 * affected superset for a visibility revocation; `all` enumerates everything,
 * which is what a `chain:*` grant or an identity restore reaches (a suspended
 * row is not in the public subset, so nothing narrower would find it).
 */
const advanceSweep = async (
  sweep: IndexSweepState,
  store: IndexReadStore,
  cap: number,
  dirty: DirtySet,
): Promise<{ sweep: IndexSweepState | null; swept: number }> => {
  if (cap <= 0) return { sweep, swept: 0 };
  const page = await store.queryIndexContent({
    ...(sweep.scope === 'public' ? { publicRead: true } : {}),
    ...(sweep.after !== null ? { after: sweep.after } : {}),
    limit: cap,
  });
  for (const row of page) dirty.contentIds.add(row.contentId);
  const last = page[page.length - 1];
  const next = page.length === cap && last ? { scope: sweep.scope, after: last.contentId } : null;
  return { sweep: next, swept: page.length };
};

// -----------------------------------------------------------------------------
// one log entry
// -----------------------------------------------------------------------------

const operationRow = (entry: LogEntry): IndexOperationRow => {
  const payload = decodeJwsUnsafe(entry.jwsToken)?.payload;
  const authoredAt = payload?.createdAt;
  const issuedAt = payload?.iat;
  const createdAt =
    typeof authoredAt === 'string'
      ? authoredAt
      : typeof issuedAt === 'number' && Number.isFinite(issuedAt)
        ? new Date(issuedAt * 1000).toISOString()
        : '';
  return {
    cid: entry.cid,
    kind: entry.kind,
    chainId: entry.chainId,
    createdAt,
    ingestedAt: entry.ingestedAt,
  };
};

/**
 * The public key ONE accepted operation's signature verified against — the
 * stored column behind `signerKey=` on /index/v0/operations.
 *
 * Resolved the same way ingestion resolved it (`resolveSignerKeyMultibase`, the
 * has-ever-proved lookup shared with the key resolver), so the string here is
 * byte-identical to the one `key=` on /index/v0/identities matches. Resolving it
 * again here rather than carrying it out of ingestion is safe because
 * `provedKeys` is monotonic: a key that resolved at acceptance still resolves.
 *
 * The kid carries the DID for every kind except an identity GENESIS, whose kid
 * is bare (the DID does not exist until the op is encoded) — there the log
 * entry's chain identifier is the signer's DID. An operation whose signer key
 * does not resolve records nothing, and then matches no `signerKey` value.
 */
const signerKeyOf = async (entry: LogEntry, store: RelayReadStore): Promise<string | null> => {
  const kid = decodeJwsUnsafe(entry.jwsToken)?.header.kid;
  if (typeof kid !== 'string' || kid === '') return null;
  const hashIdx = kid.indexOf('#');
  const did = hashIdx >= 0 ? kid.substring(0, hashIdx) : entry.chainId;
  const keyId = hashIdx >= 0 ? kid.substring(hashIdx + 1) : kid;
  if (!did || !keyId) return null;
  return resolveSignerKeyMultibase(did, keyId, store);
};

/**
 * The rows and sweeps one log entry implies.
 *
 * Mapping:
 *  - any operation      → an operation row + the signer key it verified against
 *  - identity op        → dirty that identity, record its proved keys; `delete`
 *                         sweeps the currently-public content subset, `restore`
 *                         and `update` sweep all content (a suspended row, and a
 *                         row whose grant died with a rotated-out key, are no
 *                         longer in the public subset)
 *  - content op         → dirty that content row (+ anchored identities), record
 *                         the accepted signer
 *  - artifact           → the standalone artifact row
 *  - countersign        → the countersignature row
 *  - credential grant   → dirty the att-named content rows; `chain:*` sweeps all
 *  - revocation         → ISSUER-SCOPED: resolve the revoked credential through
 *                         its own operation, dirty exactly what that grant named,
 *                         and dirty nothing at all when the relay never held it or
 *                         the revoker is not its issuer
 */
const projectLogEntry = async (
  entry: LogEntry,
  store: RelayReadStore & IndexReadStore,
  rows: RunRows,
  dirty: DirtySet,
): Promise<IndexSweepState | null> => {
  rows.operations.push(operationRow(entry));
  const signerKey = await signerKeyOf(entry, store);
  if (signerKey) rows.operationSignerKeys.push({ cid: entry.cid, publicKeyMultibase: signerKey });

  switch (entry.kind) {
    case 'identity-op': {
      dirty.identityDIDs.add(entry.chainId);
      const chain = await store.getIdentityChain(entry.chainId);
      if (chain) {
        for (const key of provedKeys(chain.state)) {
          rows.identityKeys.push({
            did: entry.chainId,
            publicKeyMultibase: key.publicKeyMultibase,
            keyId: key.id,
          });
        }
      }
      const opType = (decodeJwsUnsafe(entry.jwsToken)?.payload as Record<string, unknown>)?.[
        'type'
      ];
      if (opType === 'delete') return { scope: 'public', after: null };
      // A genesis is not always the FIRST thing this relay learns about an
      // identity. A delegated public credential is admitted on its leaf
      // signature alone, so a grant whose parent issuer is still unsynced is
      // stored while the chain that authorizes it does not yet exist here — and
      // the content it names projects as private. The parent's arrival is a
      // `create`, and without this case it dirties nothing, so the content stays
      // private until some unrelated touch happens to re-fold it. A newly-synced
      // identity can only ADD standing authority, never remove it, so the same
      // all-scope sweep restore and update already take is the right shape.
      // Coarse on purpose: the sweep is budgeted, resumable, and COALESCED, so a
      // burst of genesis operations costs one sweep, not one per identity.
      if (opType === 'create') return { scope: 'all', after: null };
      if (opType === 'restore') return { scope: 'all', after: null };
      // An `update` can change the effective key set, and a standing credential
      // whose issuer key rotated out stops granting at read time (auth.ts), so
      // every projected `publicRead` this identity backs is recomputed. The
      // scope is `all` in both directions: a rotation drops rows out of the
      // public subset, and re-adding a key brings rows that already left it back.
      if (opType === 'update') return { scope: 'all', after: null };
      return null;
    }
    case 'content-op': {
      dirty.contentIds.add(entry.chainId);
      const signerDID = (decodeJwsUnsafe(entry.jwsToken)?.payload as Record<string, unknown>)?.[
        'did'
      ];
      if (typeof signerDID === 'string') {
        rows.contentSigners.push({ contentId: entry.chainId, did: signerDID });
      }
      return null;
    }
    case 'artifact': {
      const row = artifactIndexRow(entry.cid, entry.jwsToken, entry.ingestedAt);
      if (row) rows.artifacts.push(row);
      return null;
    }
    case 'countersign': {
      const decoded = decodeJwsUnsafe(entry.jwsToken);
      const payload = decoded?.payload as Record<string, unknown> | undefined;
      rows.countersignatures.push({
        cid: typeof decoded?.header.cid === 'string' ? decoded.header.cid : entry.cid,
        targetCID: entry.chainId,
        relation: typeof payload?.['relation'] === 'string' ? payload['relation'] : null,
        jwsToken: entry.jwsToken,
        witnessDID: typeof payload?.['did'] === 'string' ? payload['did'] : '',
        createdAt: typeof payload?.['createdAt'] === 'string' ? payload['createdAt'] : '',
        ingestedAt: entry.ingestedAt,
      });
      return null;
    }
    case 'credential': {
      const { wildcard, contentIds } = contentIdsFromCredentialToken(entry.jwsToken);
      if (wildcard) return { scope: 'all', after: null };
      for (const contentId of contentIds) dirty.contentIds.add(contentId);
      return null;
    }
    case 'revocation': {
      // THE #266 NARROWING. A revocation names a credential CID. That credential
      // is itself an operation, so its grant is an O(1) lookup that survives the
      // held-credential row being dropped at commit. Two misses dirty nothing at
      // all, and between them they remove the anonymous, attacker-paced trigger:
      // a revocation for a credential this relay never held, and a revocation
      // signed by anyone other than that credential's issuer.
      const payload = decodeJwsUnsafe(entry.jwsToken)?.payload as
        Record<string, unknown> | undefined;
      const credentialCID = payload?.['credentialCID'];
      if (typeof credentialCID !== 'string') return null;
      const credentialOp = await store.getOperation(credentialCID);
      if (!credentialOp || credentialOp.chainType !== 'credential') return null;
      if (credentialOp.chainId !== entry.chainId) return null;
      const { wildcard, contentIds } = contentIdsFromCredentialToken(credentialOp.jwsToken);
      if (wildcard) return { scope: 'public', after: null };
      for (const contentId of contentIds) dirty.contentIds.add(contentId);
      return null;
    }
  }
};

// -----------------------------------------------------------------------------
// the run
// -----------------------------------------------------------------------------

/**
 * Advance the index projection by at most one budget's worth of work.
 *
 * Sweep first (outstanding fan-out is older than anything on the log tail), then
 * as many log entries as the remaining budget allows, then one `applyIndexRows`
 * and one `setIndexCursor`.
 *
 * ON FAILURE the cursor is NOT advanced and no rows are applied, so the same
 * work is retried on the next run. That is safe because every recompute is
 * convergent, and it is the honest failure mode: a projection that cannot make
 * progress stalls visibly at its cursor rather than skipping entries.
 */
export const projectIndex = async (
  store: IndexProjectionStore,
  options?: IndexProjectionOptions,
): Promise<IndexProjectionRun> => {
  const budget = options?.budget ?? DEFAULT_INDEX_PROJECTION_BUDGET;
  try {
    const stored = await store.getIndexCursor();
    const cursor: IndexCursor = stored ?? { logCursor: null, sweep: null };
    const rows = emptyRows();
    const dirty: DirtySet = { contentIds: new Set(), identityDIDs: new Set() };

    let swept = 0;
    if (cursor.sweep) {
      const advanced = await advanceSweep(cursor.sweep, store, budget, dirty);
      cursor.sweep = advanced.sweep;
      swept = advanced.swept;
    }

    let projected = 0;
    let reachedTip = false;
    const remaining = budget - swept;
    if (remaining > 0) {
      const page = await store.readLog(
        cursor.logCursor !== null
          ? { after: cursor.logCursor, limit: remaining }
          : { limit: remaining },
      );
      // A cursor this log no longer contains — a wiped or rebuilt log — restarts
      // the projection from the beginning rather than stalling on it forever.
      // Recompute is convergent, so a replay costs work and changes nothing.
      const entries = page
        ? page.entries
        : ((cursor.logCursor = null), (await store.readLog({ limit: remaining }))?.entries ?? []);
      for (const entry of entries) {
        const trigger = await projectLogEntry(entry, store, rows, dirty);
        if (trigger) cursor.sweep = widenSweep(cursor.sweep, trigger);
        cursor.logCursor = entry.cid;
        projected++;
      }
      reachedTip = entries.length < remaining;
    }

    for (const contentId of dirty.contentIds) {
      await recomputeContentRow(contentId, store, rows, dirty);
    }
    for (const did of dirty.identityDIDs) await recomputeIdentityRow(did, store, rows);

    await store.applyIndexRows(rows);
    await store.setIndexCursor(cursor);

    return { projected, swept, caughtUp: cursor.sweep === null && reachedTip };
  } catch (error) {
    logIndexProjectionError('projectIndex', error);
    return { projected: 0, swept: 0, caughtUp: false };
  }
};

/**
 * Run the projection until it is caught up, or until `maxRuns` budgets are
 * spent. The reference relay calls this after an ingest batch; a deployment that
 * would rather not pay projection latency on the accepting path runs it from a
 * timer instead (`indexProjection: 'external'`).
 */
export const drainIndexProjection = async (
  store: IndexProjectionStore,
  options?: IndexProjectionOptions & { maxRuns?: number },
): Promise<IndexProjectionRun> => {
  const maxRuns = options?.maxRuns ?? 100;
  const total: IndexProjectionRun = { projected: 0, swept: 0, caughtUp: false };
  for (let run = 0; run < maxRuns; run++) {
    const result = await projectIndex(store, options);
    total.projected += result.projected;
    total.swept += result.swept;
    total.caughtUp = result.caughtUp;
    if (result.caughtUp) break;
    // No progress and not caught up: a failed run, or a sweep that cannot
    // advance. Stop rather than spin.
    if (result.projected === 0 && result.swept === 0) break;
  }
  return total;
};

/**
 * Recompute the content rows that project a document, after its blob lands.
 *
 * A blob arrives on its own route, often after the operation that referenced it,
 * and it can turn a row's docSchema/title/profile projection from unknown to
 * known. Nothing on the operation log marks that moment, so this is the one
 * projection entry point the log does not drive. It is bounded by the reverse
 * lookup — the rows that name this documentCID and nothing else.
 */
export const projectIndexAfterBlob = async (
  documentCID: string,
  store: IndexProjectionStore,
): Promise<void> => {
  try {
    const rows = emptyRows();
    const dirty: DirtySet = { contentIds: new Set(), identityDIDs: new Set() };
    for (const contentId of await store.getIndexContentIdsByDocumentCID(documentCID)) {
      dirty.contentIds.add(contentId);
    }
    for (const contentId of dirty.contentIds) {
      await recomputeContentRow(contentId, store, rows, dirty);
    }
    for (const did of dirty.identityDIDs) await recomputeIdentityRow(did, store, rows);
    await store.applyIndexRows(rows);
  } catch (error) {
    logIndexProjectionError('projectIndexAfterBlob', error);
  }
};
