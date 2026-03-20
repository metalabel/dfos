/*

  MERKLE TREE

  Sorted binary SHA-256 Merkle tree over content identifiers.

  Pure SHA-256 construction — no dag-cbor, no CIDs. ContentIds are
  deterministic strings, already canonical. The tree is a commitment
  scheme, not content-addressed data.

    leaf:     SHA-256(UTF-8(contentId))        → 32 bytes
    interior: SHA-256(leftHash || rightHash)    → 32 bytes
    root:     final 32-byte hash, hex-encoded

*/

export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
  const buf = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buf);
};

export const toHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

export const hexToBytes = (hex: string): Uint8Array => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
};

export const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
};

/**
 * Hash a leaf node — SHA-256 of UTF-8 encoded contentId
 */
export const hashLeaf = async (contentId: string): Promise<Uint8Array> => {
  return sha256(new TextEncoder().encode(contentId));
};

/**
 * Hash an interior node — SHA-256(leftHash || rightHash)
 */
const hashInterior = async (left: Uint8Array, right: Uint8Array): Promise<Uint8Array> => {
  return sha256(concat(left, right));
};

/**
 * Build a sorted binary Merkle tree over content identifiers
 *
 * ContentIds are sorted lexicographically, hashed to leaves, then paired
 * and hashed up to the root. Odd nodes are promoted to the next level.
 *
 * Returns null root for empty input. Deduplicates contentIds.
 */
export const buildMerkleTree = async (
  contentIds: string[],
): Promise<{ root: string | null; leafCount: number }> => {
  // deduplicate and sort
  const sorted = [...new Set(contentIds)].sort();
  if (sorted.length === 0) return { root: null, leafCount: 0 };

  // hash leaves
  let level: Uint8Array[] = await Promise.all(sorted.map(hashLeaf));

  // build tree bottom-up
  while (level.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        nextLevel.push(await hashInterior(level[i]!, level[i + 1]!));
      } else {
        // odd node promoted
        nextLevel.push(level[i]!);
      }
    }
    level = nextLevel;
  }

  return { root: toHex(level[0]!), leafCount: sorted.length };
};
