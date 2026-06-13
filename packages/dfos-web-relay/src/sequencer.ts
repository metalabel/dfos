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
        await store.markOpRejected(res.cid, res.error ?? 'unknown');
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
