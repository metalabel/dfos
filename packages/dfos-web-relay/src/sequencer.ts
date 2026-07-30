/*

  SEQUENCER

  Fixed-point loop that processes unsequenced raw ops until no more
  progress is made. Separates data replication (store raw) from state
  materialization (verify + commit to chain state).

*/

import { computeOpCID, ingestOperations } from './ingest';
import type { IngestionResult, RelayStore, SequenceResult } from './types';

export { computeOpCID };

/**
 * Returns true if a rejection is retryable (a missing dependency that may
 * arrive later via sync or gossip). The sequencer branches on the STRUCTURED
 * `dependencyMissing` flag set by the ingest producer — not on substring
 * matching of the human-readable `error` string. Mirrors the Go twin's
 * structured discriminator.
 */
export const isDependencyFailure = (res: Pick<IngestionResult, 'dependencyMissing'>): boolean =>
  res.dependencyMissing === true;

/**
 * Emit the one durable trace of a permanent rejection.
 *
 * `markOpRejected` DELETES the raw op (see MemoryRelayStore.markOpRejected), and
 * the `reason` was previously passed only to be discarded — so a relay dropping
 * every op it was handed left nothing behind to explain why. This log line is
 * that explanation. Observability only: the deletion semantics are unchanged, and
 * nothing is added to the store. Mirrors the Go twin's slog call
 * (sequencer.go / relay.go).
 */
export const logOpRejected = (cid: string, reason: string): void => {
  console.warn(JSON.stringify({ event: 'relay.op.rejected', cid, reason }));
};

/**
 * Process unsequenced raw ops in a fixed-point loop until no more progress
 * is made. Returns the JWS tokens of newly sequenced ops and aggregate stats.
 */
export const sequenceOps = async (
  store: RelayStore,
): Promise<{ newOps: string[]; result: SequenceResult }> => {
  const newOps: string[] = [];
  const result: SequenceResult = { sequenced: 0, rejected: 0, pending: 0 };

  for (;;) {
    const tokens = await store.getUnsequencedOps(10000);
    if (tokens.length === 0) break;

    const results = await ingestOperations(tokens, store);

    let progress = false;
    const sequencedCIDs: string[] = [];

    for (let i = 0; i < results.length; i++) {
      const res = results[i]!;
      if (!res.cid) continue;

      if (res.status === 'new') {
        sequencedCIDs.push(res.cid);
        newOps.push(tokens[i]!);
        result.sequenced++;
        progress = true;
      } else if (res.status === 'duplicate') {
        sequencedCIDs.push(res.cid);
        progress = true;
      } else if (res.status === 'rejected' && !isDependencyFailure(res)) {
        const reason = res.error ?? 'unknown';
        logOpRejected(res.cid, reason);
        await store.markOpRejected(res.cid, reason);
        result.rejected++;
        progress = true;
      } else {
        result.pending++;
      }
    }

    if (sequencedCIDs.length > 0) {
      await store.markOpsSequenced(sequencedCIDs);
    }

    if (!progress) break;
  }

  return { newOps, result };
};
