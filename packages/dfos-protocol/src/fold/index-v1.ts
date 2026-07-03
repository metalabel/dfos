/*

  CANONICAL FOLD — INDEX / v1

  An index chain is an LWW-Map folded via the canonical fold. Each operation's
  document is an `index/v1` doc carrying an array of deltas; the resolved index
  is the fold over ALL operations (every branch) in canonical order.

  Delta shapes:
    { op: 'set',    key, value? }   — add/update entry `key` (value defaults to {})
    { op: 'remove', key }           — drop entry `key`

  `key` is a content ref (a 31-char content chain id or a CID). `value` is an
  optional metadata object ({ label?, order?, … }); a pure set-membership index
  uses the degenerate `value: {}`. Unknown delta shapes are SKIPPED
  deterministically (forward compat) — a delta whose `op` is unrecognized, whose
  `key` is not a string, or whose `set` `value` is not an object is ignored, not
  an error.

  Pure — operates over already-verified, already-resolved documents. No crypto,
  no network.

*/

import type { OrderKey } from './linearize';
import { linearize } from './linearize';
import type { LwwDelta } from './lww-map';
import { foldLwwMap } from './lww-map';

/** Canonical `$schema` URI for index documents. */
export const INDEX_V1_SCHEMA = 'https://schemas.dfos.com/index/v1';

/**
 * An index entry's metadata value. `label` and `order` are the standard hints;
 * unknown keys are preserved (forward compat). The degenerate set-membership
 * case is the empty object `{}`.
 */
export interface IndexEntry {
  /** Optional display label for the entry. */
  label?: string;
  /** Optional ordering hint (integer, per the content number-encoding rule). */
  order?: number;
  [k: string]: unknown;
}

/** A single index/v1 delta. */
export type IndexDelta =
  | { op: 'set'; key: string; value?: IndexEntry }
  | { op: 'remove'; key: string };

/** An index/v1 document — the content committed by one operation. */
export interface IndexDocument {
  $schema: string;
  deltas: IndexDelta[];
}

/**
 * An operation reduced to what the fold needs: its ordering keys plus the
 * resolved content document. `document` is whatever the operation committed by
 * CID (an `IndexDocument` for index chains; anything else is skipped).
 */
export interface FoldOperation extends OrderKey {
  /** The resolved content document this operation committed (null for delete/clear). */
  document: unknown;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Validate one delta, returning it typed if well-formed or `null` to skip.
 * Unknown `op`, non-string `key`, or a non-object `set` `value` all skip
 * deterministically.
 */
const parseIndexDelta = (raw: unknown): IndexDelta | null => {
  if (!isRecord(raw)) return null;
  const { op, key } = raw;
  if (typeof key !== 'string') return null;
  if (op === 'remove') return { op: 'remove', key };
  if (op === 'set') {
    const value = raw['value'];
    if (value === undefined) return { op: 'set', key };
    if (!isRecord(value)) return null;
    return { op: 'set', key, value: value as IndexEntry };
  }
  return null;
};

/**
 * Extract the ordered LWW-Map delta stream from a set of index operations.
 * Operations are linearized (canonical total order, branch-inclusive), then
 * each `index/v1` document's `deltas` array is flattened in array order.
 * Non-object documents, documents whose `$schema` is not `index/v1`, documents
 * without a `deltas` array, and unknown delta shapes are all skipped.
 */
const indexDeltaStream = (ops: readonly FoldOperation[]): LwwDelta<IndexEntry>[] => {
  const stream: LwwDelta<IndexEntry>[] = [];
  for (const op of linearize(ops)) {
    const doc = op.document;
    if (!isRecord(doc) || doc['$schema'] !== INDEX_V1_SCHEMA) continue;
    const deltas = doc['deltas'];
    if (!Array.isArray(deltas)) continue;
    for (const raw of deltas) {
      const delta = parseIndexDelta(raw);
      if (!delta) continue;
      if (delta.op === 'remove') stream.push({ op: 'remove', key: delta.key });
      else stream.push({ op: 'set', key: delta.key, value: delta.value ?? {} });
    }
  }
  return stream;
};

/**
 * Fold a set of index/v1 operations into the resolved index map.
 *
 * The fold is branch-INCLUSIVE — pass every operation in the chain's log, not
 * just the selected-head branch. Concurrent forks converge: any permutation of
 * the same operation set folds to an equal map.
 *
 * Precondition: the chain is not delete-terminal. If the selected head branch
 * is a `delete`, the chain is deleted and the fold is moot — the caller checks
 * `isDeleted` (from `verifyContentChain`) and does not fold a deleted chain.
 */
export const foldIndexV1 = (ops: readonly FoldOperation[]): Map<string, IndexEntry> =>
  foldLwwMap(indexDeltaStream(ops));
