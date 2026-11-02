/*

  CONTENT DAG

  Verification of a branch-inclusive content log. A content chain is a DAG
  (PROTOCOL, Chain validity): two operations naming the same
  `previousOperationCID` are a fork, and both branches are accepted. A relay's
  per-chain log enumerates every branch it accepted, so a verifier folding it
  applies head selection itself rather than taking the relay's word for which
  operation is the head.

  Each operation is verified against its parent's verified state, once, with the
  result memoized per CID so a shared prefix verifies once however many branches
  hang off it. An operation that fails is dropped together with its whole
  subtree: its descendants extend a state that does not exist. The head is
  chosen among the surviving tips with `compareHeadPreference`, the same
  comparator the relays and the canonical fold use.

  A failure that is only a dependency miss (an identity or key this resolver
  does not hold yet) is not a verdict on the operation, so it is rethrown rather
  than dropped: dropping it would re-select the head on a lookup that may
  succeed later.

*/

import type { ResolvedIdentity, RevocationChecker } from '../credentials';
import { decodeJwsUnsafe } from '../crypto';
import { carryDependencyMissing, isDependencyMissing } from '../dependency';
import { compareHeadPreference, type OrderKey } from '../fold/linearize';
import {
  verifyContentChain,
  verifyContentExtensionFromTrustedState,
  type VerifiedContentChain,
} from './content-chain';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

/** One verified operation: the chain state it folds to, and its `createdAt`. */
export interface ContentDagNode {
  state: VerifiedContentChain;
  createdAt: string;
}

/** An operation the DAG verify dropped, and why. */
export interface ContentDagRejection {
  /** The operation's CID as its JWS header names it; `''` when none decodes. */
  cid: string;
  reason: string;
}

export interface VerifiedContentDag {
  /** Chain state at the selected head. */
  head: VerifiedContentChain;
  /** `createdAt` of the head operation. */
  headCreatedAt: string;
  /** JWS tokens of the head's lineage, genesis first: the linear log. */
  headLineage: string[];
  /** Surviving tips, most head-preferred first. `tips[0]` is the head. */
  tips: OrderKey[];
  /** Dropped operations, a failing op and each op of its subtree. */
  rejected: ContentDagRejection[];
  /** Every surviving operation's verified node, keyed by CID. */
  nodes: Record<string, ContentDagNode>;
}

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

interface DecodedOp {
  jws: string;
  cid: string;
  previousCID: string | null;
  createdAt: string;
}

const decodeOp = (jws: string): DecodedOp | null => {
  const decoded = decodeJwsUnsafe(jws);
  if (!decoded) return null;
  const cid = decoded.header.cid;
  if (typeof cid !== 'string' || cid === '') return null;
  const payload = decoded.payload as Record<string, unknown>;
  const prev = payload['previousOperationCID'];
  const createdAt = payload['createdAt'];
  return {
    jws,
    cid,
    previousCID: typeof prev === 'string' ? prev : null,
    createdAt: typeof createdAt === 'string' ? createdAt : '',
  };
};

/**
 * Verify a branch-inclusive content log and select its head.
 *
 * Genesis is the single operation with no `previousOperationCID`. A log with
 * none, or with more than one, is a hard error, and so is a genesis that fails
 * verification: nothing survives it. Every other failure drops the operation
 * and its subtree into `rejected`.
 *
 * `known` seeds the memo with nodes the caller already verified (a client's
 * cache): an operation whose CID is in it is not re-verified. The caller
 * guarantees each seeded node was verified from the exact JWS token served.
 */
export const verifyContentDag = async (input: {
  log: string[];
  /** See `verifyContentChain`. */
  resolveKey: (kid: string, basis?: string) => Promise<Uint8Array>;
  /** See `verifyContentChain`. */
  enforceAuthorization?: boolean;
  /** See `verifyContentChain`. */
  resolveIdentity?: (did: string, basis?: string) => Promise<ResolvedIdentity | undefined>;
  /** See `verifyContentChain`. */
  isRevoked?: RevocationChecker;
  /** Already-verified nodes, keyed by operation CID. */
  known?: Readonly<Record<string, ContentDagNode>>;
}): Promise<VerifiedContentDag> => {
  if (input.log.length === 0) throw new Error('log must have at least one operation');

  const rejected: ContentDagRejection[] = [];
  const byCID = new Map<string, DecodedOp>();
  const children = new Map<string, DecodedOp[]>();
  const geneses: DecodedOp[] = [];

  for (const [idx, jws] of input.log.entries()) {
    const op = decodeOp(jws);
    if (!op) {
      rejected.push({ cid: '', reason: `log[${idx}]: failed to decode operation` });
      continue;
    }
    const seen = byCID.get(op.cid);
    if (seen) {
      if (seen.jws !== jws) rejected.push({ cid: op.cid, reason: 'duplicate operation CID' });
      continue;
    }
    byCID.set(op.cid, op);
    if (op.previousCID === null) {
      geneses.push(op);
      continue;
    }
    const siblings = children.get(op.previousCID);
    if (siblings) siblings.push(op);
    else children.set(op.previousCID, [op]);
  }

  if (geneses.length === 0) throw new Error('content log has no genesis operation');
  if (geneses.length > 1) throw new Error('content log has more than one genesis operation');
  const genesis = geneses[0]!;

  const verifyOptions = {
    resolveKey: input.resolveKey,
    ...(input.enforceAuthorization !== undefined
      ? { enforceAuthorization: input.enforceAuthorization }
      : {}),
    ...(input.resolveIdentity ? { resolveIdentity: input.resolveIdentity } : {}),
    ...(input.isRevoked ? { isRevoked: input.isRevoked } : {}),
  };

  const nodes: Record<string, ContentDagNode> = {};
  const seeded = input.known?.[genesis.cid];
  if (seeded) {
    nodes[genesis.cid] = seeded;
  } else {
    const state = await verifyContentChain({ log: [genesis.jws], ...verifyOptions });
    nodes[genesis.cid] = { state, createdAt: genesis.createdAt };
  }

  const rejectSubtree = (root: DecodedOp): void => {
    const stack = [...(children.get(root.cid) ?? [])];
    while (stack.length > 0) {
      const op = stack.pop()!;
      rejected.push({ cid: op.cid, reason: `ancestor ${root.cid} was rejected` });
      stack.push(...(children.get(op.cid) ?? []));
    }
  };

  // breadth-first from genesis: a child verifies only once its parent has
  const queue: DecodedOp[] = [genesis];
  while (queue.length > 0) {
    const parent = queue.shift()!;
    const parentNode = nodes[parent.cid]!;
    for (const op of children.get(parent.cid) ?? []) {
      const known = input.known?.[op.cid];
      if (known) {
        nodes[op.cid] = known;
        queue.push(op);
        continue;
      }
      try {
        const r = await verifyContentExtensionFromTrustedState({
          currentState: parentNode.state,
          lastCreatedAt: parentNode.createdAt,
          newOp: op.jws,
          ...verifyOptions,
        });
        nodes[op.cid] = { state: r.state, createdAt: r.createdAt };
        queue.push(op);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'verification failed';
        if (isDependencyMissing(err)) {
          throw carryDependencyMissing(err, new Error(`operation ${op.cid}: ${message}`));
        }
        rejected.push({ cid: op.cid, reason: message });
        rejectSubtree(op);
      }
    }
  }

  // an op whose parent is not in the log is never reached from genesis
  const reached = new Set(rejected.map((r) => r.cid));
  for (const op of byCID.values()) {
    if (nodes[op.cid] || reached.has(op.cid)) continue;
    rejected.push({ cid: op.cid, reason: 'previous operation is not in the log' });
  }

  const hasSurvivingChild = new Set<string>();
  for (const cid of Object.keys(nodes)) {
    const prev = byCID.get(cid)!.previousCID;
    if (prev !== null) hasSurvivingChild.add(prev);
  }
  const tips: OrderKey[] = Object.keys(nodes)
    .filter((cid) => !hasSurvivingChild.has(cid))
    .map((cid) => ({ cid, createdAt: nodes[cid]!.createdAt }))
    .sort(compareHeadPreference);

  const head = tips[0]!;
  const headLineage: string[] = [];
  for (let cursor: string | null = head.cid; cursor !== null;) {
    const op: DecodedOp = byCID.get(cursor)!;
    headLineage.unshift(op.jws);
    cursor = op.previousCID;
  }

  return {
    head: nodes[head.cid]!.state,
    headCreatedAt: head.createdAt,
    headLineage,
    tips,
    rejected,
    nodes,
  };
};
