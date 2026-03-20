/*

  MERKLE PROOF

  Inclusion proof generation and verification for the sorted binary
  SHA-256 Merkle tree.

*/

import { buildMerkleTree, concat, hashLeaf, hexToBytes, sha256, toHex } from './tree';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface MerkleProof {
  /** The contentId being proven */
  contentId: string;
  /** Hex SHA-256 root of the tree */
  root: string;
  /** Sibling hashes along the path from leaf to root */
  path: Array<{
    /** Hex SHA-256 of sibling node */
    hash: string;
    /** Position of the sibling relative to the current node */
    position: 'left' | 'right';
  }>;
}

// -----------------------------------------------------------------------------
// proof generation
// -----------------------------------------------------------------------------

/**
 * Generate an inclusion proof for a contentId in the set
 *
 * Returns null if the contentId is not in the set.
 */
export const generateMerkleProof = async (
  contentIds: string[],
  targetId: string,
): Promise<MerkleProof | null> => {
  // deduplicate and sort (same as buildMerkleTree)
  const sorted = [...new Set(contentIds)].sort();
  const targetIdx = sorted.indexOf(targetId);
  if (targetIdx < 0) return null;

  // build the tree root for the proof
  const { root } = await buildMerkleTree(sorted);
  if (!root) return null;

  // hash all leaves
  const leaves: Uint8Array[] = await Promise.all(sorted.map(hashLeaf));

  // walk the tree, collecting sibling hashes
  const path: MerkleProof['path'] = [];
  let level = leaves;
  let idx = targetIdx;

  while (level.length > 1) {
    const nextLevel: Uint8Array[] = [];
    const nextIdx = Math.floor(idx / 2);

    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        // paired
        if (i === idx || i + 1 === idx) {
          const siblingIdx = i === idx ? i + 1 : i;
          path.push({
            hash: toHex(level[siblingIdx]!),
            position: siblingIdx < idx ? 'left' : 'right',
          });
        }
        const interior = await sha256(concat(level[i]!, level[i + 1]!));
        nextLevel.push(interior);
      } else {
        // odd node promoted — no sibling to record
        nextLevel.push(level[i]!);
      }
    }

    level = nextLevel;
    idx = nextIdx;
  }

  return { contentId: targetId, root, path };
};

// -----------------------------------------------------------------------------
// proof verification
// -----------------------------------------------------------------------------

/**
 * Verify a Merkle inclusion proof
 *
 * Recomputes the root from the leaf and proof path, compares to the claimed root.
 */
export const verifyMerkleProof = async (proof: MerkleProof): Promise<boolean> => {
  let current = await hashLeaf(proof.contentId);

  for (const step of proof.path) {
    const sibling = hexToBytes(step.hash);
    if (step.position === 'left') {
      current = await sha256(concat(sibling, current));
    } else {
      current = await sha256(concat(current, sibling));
    }
  }

  return toHex(current) === proof.root;
};
