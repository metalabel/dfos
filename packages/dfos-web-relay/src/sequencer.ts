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
 * nothing is added to the store. The event string and both field names match the
 * Go twin's slog call (sequencer.go / relay.go) so one query shape works across
 * implementations.
 *
 * One line per rejected op on an unauthenticated ingest endpoint is a considered
 * tradeoff: a flood of junk ops does amplify into logs, but each such op already
 * cost signature verification and store reads, so the marginal write is small next
 * to the work it reports — and a silent drop is the failure mode that actually goes
 * undiagnosed.
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
    const pendingOps = await store.getUnsequencedOps(10000);
    if (pendingOps.length === 0) break;

    const indexedResults: Array<{ index: number; result: IngestionResult }> = [];
    for (const origin of ['direct', 'peer'] as const) {
      const partition = pendingOps
        .map((op, index) => ({ op, index }))
        .filter(({ op }) => op.origin === origin);
      if (partition.length === 0) continue;
      const partitionResults = await ingestOperations(
        partition.map(({ op }) => op.jwsToken),
        store,
        { admissionMode: origin === 'peer' ? 'historical' : 'current' },
      );
      for (let i = 0; i < partition.length; i++) {
        indexedResults.push({ index: partition[i]!.index, result: partitionResults[i]! });
      }
    }
    const results = indexedResults.sort((a, b) => a.index - b.index).map(({ result }) => result);

    let progress = false;
    const sequencedCIDs: string[] = [];

    for (let i = 0; i < results.length; i++) {
      const res = results[i]!;
      if (!res.cid) continue;

      if (res.status === 'new') {
        sequencedCIDs.push(res.cid);
        newOps.push(pendingOps[i]!.jwsToken);
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
