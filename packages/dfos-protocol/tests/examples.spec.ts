/**
 * Validate example chain fixtures
 *
 * Loads the static JSON fixtures from examples/ and verifies them against
 * the protocol implementation. This test is the validator, not the generator.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  decodeMultikey,
  verifyBeacon,
  verifyContentChain,
  verifyIdentityChain,
} from '../src/chain';
import type { VerifiedContentChain } from '../src/chain';
import type { VerifiedIdentity } from '../src/chain/schemas';
import { buildMerkleTree, verifyMerkleProof } from '../src/merkle';
import type { MerkleProof } from '../src/merkle';

const examplesDir = join(import.meta.dirname, '..', 'examples');

const loadFixture = (name: string) => {
  const raw = readFileSync(join(examplesDir, name), 'utf-8');
  return JSON.parse(raw);
};

const fixtures = readdirSync(examplesDir)
  .filter((f) => f.endsWith('.json'))
  .sort();

describe('example fixtures', () => {
  it('has all expected fixture files', () => {
    expect(fixtures).toEqual([
      'beacon.json',
      'content-delete.json',
      'content-lifecycle.json',
      'identity-delete.json',
      'identity-genesis.json',
      'identity-rotation.json',
      'merkle-tree.json',
    ]);
  });

  describe('identity chains', () => {
    const identityFixtures = fixtures.filter((f) => f.startsWith('identity-'));

    for (const file of identityFixtures) {
      it(`verifies ${file}`, async () => {
        const fixture = loadFixture(file);
        expect(fixture.type).toBe('identity');
        expect(fixture.chain.length).toBeGreaterThan(0);

        const result: VerifiedIdentity = await verifyIdentityChain({
          didPrefix: 'did:dfos',
          log: fixture.chain,
        });

        expect(result.did).toBe(fixture.expected.did);
        expect(result.isDeleted).toBe(fixture.expected.isDeleted);
        expect(result.controllerKeys).toEqual(fixture.expected.controllerKeys);
      });
    }
  });

  describe('content chains', () => {
    const contentFixtures = fixtures.filter((f) => f.startsWith('content-'));

    for (const file of contentFixtures) {
      it(`verifies ${file}`, async () => {
        const fixture = loadFixture(file);
        expect(fixture.type).toBe('content');
        expect(fixture.chain.length).toBeGreaterThan(0);
        expect(fixture.signerPublicKey).toBeDefined();

        const { keyBytes } = decodeMultikey(fixture.signerPublicKey);

        const result: VerifiedContentChain = await verifyContentChain({
          log: fixture.chain,
          resolveKey: async () => keyBytes,
        });

        expect(result.contentId).toBe(fixture.expected.contentId);
        expect(result.isDeleted).toBe(fixture.expected.isDeleted);
        expect(result.currentDocumentCID).toBe(fixture.expected.currentDocumentCID);
        expect(result.length).toBe(fixture.expected.length);
      });
    }
  });

  describe('merkle tree', () => {
    it('verifies merkle-tree.json', async () => {
      const fixture = loadFixture('merkle-tree.json');
      expect(fixture.type).toBe('merkle');

      const { root, leafCount } = await buildMerkleTree(fixture.contentIds);
      expect(root).toBe(fixture.expected.root);
      expect(leafCount).toBe(fixture.expected.leafCount);

      // verify inclusion proof for charlie
      const proof: MerkleProof = fixture.expected.charlieProof;
      const valid = await verifyMerkleProof(proof);
      expect(valid).toBe(true);
    });
  });

  describe('beacon', () => {
    it('verifies beacon.json controller JWS', async () => {
      const fixture = loadFixture('beacon.json');
      expect(fixture.type).toBe('beacon');

      const { keyBytes } = decodeMultikey(fixture.controllerPublicKey);
      const result = await verifyBeacon({
        jwsToken: fixture.controllerJws,
        resolveKey: async () => keyBytes,
      });

      expect(result.beaconCID).toBe(fixture.expected.beaconCID);
      expect(result.payload.did).toBe(fixture.expected.did);
      expect(result.payload.merkleRoot).toBe(fixture.expected.merkleRoot);
    });
  });
});
