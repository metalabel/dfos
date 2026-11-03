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

  An operation dated more than 24 hours past the verifier's clock is rejected
  before it can be admitted (PROTOCOL, Future timestamp bound): head selection
  prefers the highest `createdAt`, so an unbounded one would hold the head
  forever.

  Membership is never read off a plain object: a header CID is attacker-chosen,
  and one spelled `constructor` would otherwise find an inherited property.

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
import { parseProtocolTimestampUnix } from './schemas';

/** How far past the verifier's clock an operation's `createdAt` may be. */
export const MAX_FUTURE_TIMESTAMP_MS = 24 * 60 * 60 * 1000;

const beyondFutureBound = (createdAt: string, nowMs: number): boolean => {
  // an off-grammar timestamp is the schema's to reject; past the grammar check
  // the full millisecond instant is compared, as relay ingest does
  if (parseProtocolTimestampUnix(createdAt) === null) return false;
  return Date.parse(createdAt) > nowMs + MAX_FUTURE_TIMESTAMP_MS;
};

const FUTURE_BOUND_REASON = 'createdAt is more than 24 hours in the future';

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
  /** Every surviving operation's verified node, keyed by CID. Read it by own
   *  key only (`Object.hasOwn`): a CID is attacker-chosen. */
  nodes: Record<string, ContentDagNode>;
}

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

interface DecodedOp {
  jws: string;
  cid: string;
  /** A `create` is the genesis whatever members it carries. */
  isCreate: boolean;
  /** The parent; `null` for a create, and for a non-create that names none. */
  previousCID: string | null;
  createdAt: string;
}

const decodeOp = (jws: string): DecodedOp | null => {
  const decoded = decodeJwsUnsafe(jws);
  if (!decoded) return null;
  const cid = decoded.header.cid;
  if (typeof cid !== 'string' || cid === '') return null;
  const payload = decoded.payload as Record<string, unknown>;
  const isCreate = payload['type'] === 'create';
  // a create's previousOperationCID, if any, is an unknown extension member
  const prev = isCreate ? undefined : payload['previousOperationCID'];
  const createdAt = payload['createdAt'];
  return {
    jws,
    cid,
    isCreate,
    previousCID: typeof prev === 'string' ? prev : null,
    createdAt: typeof createdAt === 'string' ? createdAt : '',
  };
};

/**
 * Verify a branch-inclusive content log and select its head.
 *
 * Genesis is the single `create` operation, whatever other members it carries;
 * a non-create that names no parent is an orphan. A log with
 * none, or with more than one, is a hard error, and so is a genesis that fails
 * verification: nothing survives it. So is a CID served with two different
 * tokens. Every other failure drops the operation
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
  /** Already-verified nodes, keyed by operation CID. Read by own key only. */
  known?: Readonly<Record<string, ContentDagNode>>;
  /** The verifier's clock (unix ms) for the future timestamp bound. Default `Date.now`. */
  now?: () => number;
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
      // Two different operations claiming one CID is not a branch: at most one
      // of them derives it, and which one a verifier sees first is the relay's
      // choice. Refuse the log rather than let serving order decide.
      if (seen.jws !== jws) {
        throw new Error(`content log serves conflicting operations under CID ${op.cid}`);
      }
      continue;
    }
    byCID.set(op.cid, op);
    if (op.isCreate) {
      geneses.push(op);
      continue;
    }
    if (op.previousCID === null) continue; // never reached: rejected as an orphan
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

  const nowMs = (input.now ?? Date.now)();
  const known = input.known;
  const knownNode = (cid: string): ContentDagNode | undefined =>
    known !== undefined && Object.hasOwn(known, cid) ? known[cid] : undefined;

  const nodes = new Map<string, ContentDagNode>();
  if (beyondFutureBound(genesis.createdAt, nowMs)) {
    throw new Error(`genesis operation ${genesis.cid}: ${FUTURE_BOUND_REASON}`);
  }
  const seeded = knownNode(genesis.cid);
  if (seeded) {
    nodes.set(genesis.cid, seeded);
  } else {
    const state = await verifyContentChain({ log: [genesis.jws], ...verifyOptions });
    nodes.set(genesis.cid, { state, createdAt: genesis.createdAt });
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
    const parentNode = nodes.get(parent.cid)!;
    for (const op of children.get(parent.cid) ?? []) {
      if (beyondFutureBound(op.createdAt, nowMs)) {
        rejected.push({ cid: op.cid, reason: FUTURE_BOUND_REASON });
        rejectSubtree(op);
        continue;
      }
      const seededNode = knownNode(op.cid);
      if (seededNode) {
        nodes.set(op.cid, seededNode);
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
        nodes.set(op.cid, { state: r.state, createdAt: r.createdAt });
        queue.push(op);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'verification failed';
        if (isDependencyMissing(err)) {
          throw carryDependencyMissing(
            err,
            new Error(`operation ${op.cid}: ${message}`, { cause: err }),
          );
        }
        rejected.push({ cid: op.cid, reason: message });
        rejectSubtree(op);
      }
    }
  }

  // an op whose parent is not in the log is never reached from genesis
  const reached = new Set(rejected.map((r) => r.cid));
  for (const op of byCID.values()) {
    if (nodes.has(op.cid) || reached.has(op.cid)) continue;
    rejected.push({ cid: op.cid, reason: 'previous operation is not in the log' });
  }

  const hasSurvivingChild = new Set<string>();
  for (const cid of nodes.keys()) {
    const prev = byCID.get(cid)!.previousCID;
    if (prev !== null) hasSurvivingChild.add(prev);
  }
  const tips: OrderKey[] = [...nodes.entries()]
    .filter(([cid]) => !hasSurvivingChild.has(cid))
    .map(([cid, node]) => ({ cid, createdAt: node.createdAt }))
    .sort(compareHeadPreference);

  const head = tips[0]!;
  const headLineage: string[] = [];
  for (let cursor: string | null = head.cid; cursor !== null;) {
    const op: DecodedOp = byCID.get(cursor)!;
    headLineage.unshift(op.jws);
    cursor = op.previousCID;
  }

  return {
    head: nodes.get(head.cid)!.state,
    headCreatedAt: head.createdAt,
    headLineage,
    tips,
    rejected,
    // a plain object so it persists as JSON; `fromEntries` defines own
    // properties, so even a `__proto__` key stays data
    nodes: Object.fromEntries(nodes),
  };
};
