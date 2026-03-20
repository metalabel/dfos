import { describe, expect, it } from 'vitest';
import {
  buildMerkleTree,
  generateMerkleProof,
  hashLeaf,
  hexToBytes,
  verifyMerkleProof,
} from '../src/merkle';
import type { MerkleProof } from '../src/merkle';

// =============================================================================
// helpers
// =============================================================================

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

// =============================================================================
// buildMerkleTree
// =============================================================================

describe('buildMerkleTree', () => {
  it('should return null root and leafCount 0 for empty set', async () => {
    const result = await buildMerkleTree([]);
    expect(result.root).toBeNull();
    expect(result.leafCount).toBe(0);
  });

  it('should return the leaf hash as root for a single contentId', async () => {
    const id = 'content_abc123';
    const leafHash = toHex(await hashLeaf(id));
    const result = await buildMerkleTree([id]);
    expect(result.root).toBe(leafHash);
    expect(result.leafCount).toBe(1);
  });

  it('should produce a deterministic root for two contentIds regardless of input order', async () => {
    const a = 'content_alpha';
    const b = 'content_beta';
    const r1 = await buildMerkleTree([a, b]);
    const r2 = await buildMerkleTree([b, a]);
    expect(r1.root).toBe(r2.root);
    expect(r1.leafCount).toBe(2);
    expect(r2.leafCount).toBe(2);
  });

  it('should handle three contentIds (odd-node promotion)', async () => {
    const ids = ['x', 'y', 'z'];
    const result = await buildMerkleTree(ids);
    expect(result.root).not.toBeNull();
    expect(result.leafCount).toBe(3);

    // reversed input order should yield the same root
    const reversed = await buildMerkleTree([...ids].reverse());
    expect(reversed.root).toBe(result.root);
  });

  it('should produce a deterministic root for a larger set (7 items)', async () => {
    const ids = ['item_1', 'item_2', 'item_3', 'item_4', 'item_5', 'item_6', 'item_7'];
    const r1 = await buildMerkleTree(ids);
    const r2 = await buildMerkleTree([...ids].reverse());
    const r3 = await buildMerkleTree([...ids].sort(() => 0.5 - Math.random()));
    expect(r1.root).not.toBeNull();
    expect(r1.leafCount).toBe(7);
    expect(r1.root).toBe(r2.root);
    expect(r1.root).toBe(r3.root);
  });

  it('should deduplicate contentIds', async () => {
    const ids = ['dup', 'dup', 'dup', 'other'];
    const result = await buildMerkleTree(ids);
    expect(result.leafCount).toBe(2);

    const deduped = await buildMerkleTree(['dup', 'other']);
    expect(result.root).toBe(deduped.root);
  });

  it('should always produce a 64-char lowercase hex root', async () => {
    const cases = [['a'], ['a', 'b'], ['a', 'b', 'c'], ['x', 'y', 'z', 'w', 'v']];
    for (const ids of cases) {
      const result = await buildMerkleTree(ids);
      expect(result.root).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('should produce the same root for identical inputs across calls', async () => {
    const ids = ['deterministic', 'test', 'vector'];
    const results = await Promise.all([
      buildMerkleTree(ids),
      buildMerkleTree(ids),
      buildMerkleTree(ids),
    ]);
    expect(results[0]!.root).toBe(results[1]!.root);
    expect(results[1]!.root).toBe(results[2]!.root);
  });
});

// =============================================================================
// generateMerkleProof
// =============================================================================

describe('generateMerkleProof', () => {
  it('should return a valid proof for an existing contentId', async () => {
    const ids = ['alpha', 'bravo', 'charlie', 'delta'];
    const proof = await generateMerkleProof(ids, 'bravo');
    expect(proof).not.toBeNull();
    expect(proof!.contentId).toBe('bravo');
    expect(proof!.root).toMatch(/^[0-9a-f]{64}$/);
    expect(proof!.path.length).toBeGreaterThan(0);

    for (const step of proof!.path) {
      expect(step.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(['left', 'right']).toContain(step.position);
    }
  });

  it('should return null for a non-existent contentId', async () => {
    const ids = ['alpha', 'bravo', 'charlie'];
    const proof = await generateMerkleProof(ids, 'missing');
    expect(proof).toBeNull();
  });

  it('should return a proof with root matching buildMerkleTree root', async () => {
    const ids = ['one', 'two', 'three', 'four', 'five'];
    const { root } = await buildMerkleTree(ids);
    const proof = await generateMerkleProof(ids, 'three');
    expect(proof).not.toBeNull();
    expect(proof!.root).toBe(root);
  });

  it('should return an empty path for a single-item set', async () => {
    const proof = await generateMerkleProof(['solo'], 'solo');
    expect(proof).not.toBeNull();
    expect(proof!.path).toHaveLength(0);
    expect(proof!.contentId).toBe('solo');

    // root should be the leaf hash
    const leafHash = toHex(await hashLeaf('solo'));
    expect(proof!.root).toBe(leafHash);
  });
});

// =============================================================================
// verifyMerkleProof
// =============================================================================

describe('verifyMerkleProof', () => {
  it('should verify a valid proof', async () => {
    const ids = ['apple', 'banana', 'cherry', 'date', 'elderberry'];
    const proof = await generateMerkleProof(ids, 'cherry');
    expect(proof).not.toBeNull();
    const valid = await verifyMerkleProof(proof!);
    expect(valid).toBe(true);
  });

  it('should reject a proof with a tampered root', async () => {
    const ids = ['apple', 'banana', 'cherry'];
    const proof = await generateMerkleProof(ids, 'banana');
    expect(proof).not.toBeNull();

    const tampered: MerkleProof = {
      ...proof!,
      root: 'ff'.repeat(32),
    };
    const valid = await verifyMerkleProof(tampered);
    expect(valid).toBe(false);
  });

  it('should reject a proof with the wrong contentId', async () => {
    const ids = ['apple', 'banana', 'cherry'];
    const proof = await generateMerkleProof(ids, 'banana');
    expect(proof).not.toBeNull();

    const wrongId: MerkleProof = {
      ...proof!,
      contentId: 'forged_content',
    };
    const valid = await verifyMerkleProof(wrongId);
    expect(valid).toBe(false);
  });

  it('should verify proofs for all items in a set', async () => {
    const ids = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf'];

    for (const id of ids) {
      const proof = await generateMerkleProof(ids, id);
      expect(proof).not.toBeNull();
      const valid = await verifyMerkleProof(proof!);
      expect(valid).toBe(true);
    }
  });

  it('should verify a proof for a single-item set', async () => {
    const proof = await generateMerkleProof(['only'], 'only');
    expect(proof).not.toBeNull();
    const valid = await verifyMerkleProof(proof!);
    expect(valid).toBe(true);
  });

  it('should verify a proof for a two-item set', async () => {
    const ids = ['left', 'right'];
    for (const id of ids) {
      const proof = await generateMerkleProof(ids, id);
      expect(proof).not.toBeNull();
      const valid = await verifyMerkleProof(proof!);
      expect(valid).toBe(true);
    }
  });

  it('should reject a proof with a tampered path hash', async () => {
    const ids = ['a', 'b', 'c', 'd'];
    const proof = await generateMerkleProof(ids, 'b');
    expect(proof).not.toBeNull();
    expect(proof!.path.length).toBeGreaterThan(0);

    const tampered: MerkleProof = {
      ...proof!,
      path: proof!.path.map((step, i) => (i === 0 ? { ...step, hash: '00'.repeat(32) } : step)),
    };
    const valid = await verifyMerkleProof(tampered);
    expect(valid).toBe(false);
  });
});

// =============================================================================
// hashLeaf and hexToBytes
// =============================================================================

describe('hashLeaf', () => {
  it('should produce a 32-byte hash', async () => {
    const hash = await hashLeaf('test');
    expect(hash.length).toBe(32);
  });

  it('should be deterministic', async () => {
    const h1 = await hashLeaf('deterministic');
    const h2 = await hashLeaf('deterministic');
    expect(h1).toEqual(h2);
  });

  it('should produce different hashes for different inputs', async () => {
    const h1 = await hashLeaf('input_a');
    const h2 = await hashLeaf('input_b');
    expect(toHex(h1)).not.toBe(toHex(h2));
  });
});

describe('hexToBytes', () => {
  it('should round-trip with toHex', async () => {
    const hash = await hashLeaf('round-trip-test');
    const hex = toHex(hash);
    const bytes = hexToBytes(hex);
    expect(bytes).toEqual(hash);
  });

  it('should decode a known hex string', () => {
    const bytes = hexToBytes('deadbeef');
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it('should return empty array for empty string', () => {
    const bytes = hexToBytes('');
    expect(bytes.length).toBe(0);
  });
});
