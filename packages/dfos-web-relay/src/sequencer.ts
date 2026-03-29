/*

  SEQUENCER

  Fixed-point loop that processes unsequenced raw ops until no more
  progress is made. Separates data replication (store raw) from state
  materialization (verify + commit to chain state).

*/

import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { ingestOperations } from './ingest';
import type { RelayStore, SequenceResult } from './types';

/**
 * Returns true if the rejection is due to a missing dependency that may
 * arrive later via sync or gossip. Only these specific patterns are
 * retryable — everything else is treated as permanent.
 */
export const isDependencyFailure = (error: string): boolean => {
  const patterns = [
    'unknown previous operation',
    'unknown identity:',
    'content chain not found:',
    'failed to compute state at fork point:',
  ];
  return patterns.some((p) => error.includes(p));
};

/** Derive the operation CID from a JWS token */
export const computeOpCID = async (jwsToken: string): Promise<string | undefined> => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return undefined;
  const encoded = await dagCborCanonicalEncode(decoded.payload);
  return encoded.cid.toString();
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
      } else if (res.status === 'rejected' && !isDependencyFailure(res.error ?? '')) {
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
