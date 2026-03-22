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
import { decodeCredentialUnsafe, verifyCredential } from '../src/credentials';
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
      'content-delegated.json',
      'content-delete.json',
      'content-lifecycle.json',
      'credential-read.json',
      'credential-write.json',
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
    const contentFixtures = fixtures.filter(
      (f) => f.startsWith('content-') && !f.startsWith('content-delegated'),
    );

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

  describe('delegated content chain', () => {
    it('verifies content-delegated.json', async () => {
      const fixture = loadFixture('content-delegated.json');
      expect(fixture.type).toBe('content-delegated');
      expect(fixture.chain.length).toBe(2);

      const creatorKey = decodeMultikey(fixture.creatorPublicKey).keyBytes;
      const delegateKey = decodeMultikey(fixture.delegatePublicKey).keyBytes;

      // decode the VC to get the creator's kid for key resolution
      const vcDecoded = decodeCredentialUnsafe(fixture.authorization);
      expect(vcDecoded).not.toBeNull();
      const vcKid = vcDecoded!.header.kid;

      const result: VerifiedContentChain = await verifyContentChain({
        log: fixture.chain,
        resolveKey: async (kid: string) => {
          // creator's kid appears in genesis op and in the VC header
          if (kid === vcKid || kid.includes(fixture.expected.creatorDID.split(':')[2])) {
            return creatorKey;
          }
          return delegateKey;
        },
        enforceAuthorization: true,
      });

      expect(result.contentId).toBe(fixture.expected.contentId);
      expect(result.creatorDID).toBe(fixture.expected.creatorDID);
      expect(result.isDeleted).toBe(fixture.expected.isDeleted);
      expect(result.currentDocumentCID).toBe(fixture.expected.currentDocumentCID);
      expect(result.length).toBe(fixture.expected.length);
    });
  });

  describe('credentials', () => {
    it('verifies credential-write.json broad credential', async () => {
      const fixture = loadFixture('credential-write.json');
      expect(fixture.type).toBe('credential');

      const { keyBytes } = decodeMultikey(fixture.issuerPublicKey);
      const result = verifyCredential({
        token: fixture.broadCredential,
        publicKey: keyBytes,
        currentTime: Math.floor(new Date('2026-06-01T00:00:00.000Z').getTime() / 1000),
      });

      expect(result.iss).toBe(fixture.expected.iss);
      expect(result.sub).toBe(fixture.expected.sub);
      expect(result.type).toBe(fixture.expected.vcType);
      expect(result.contentId).toBeUndefined();
    });

    it('verifies credential-write.json narrow credential', async () => {
      const fixture = loadFixture('credential-write.json');
      const { keyBytes } = decodeMultikey(fixture.issuerPublicKey);

      const result = verifyCredential({
        token: fixture.narrowCredential,
        publicKey: keyBytes,
        currentTime: Math.floor(new Date('2026-06-01T00:00:00.000Z').getTime() / 1000),
      });

      expect(result.contentId).toBe(fixture.expected.narrowContentId);
    });

    it('verifies credential-read.json', async () => {
      const fixture = loadFixture('credential-read.json');
      expect(fixture.type).toBe('credential');

      const { keyBytes } = decodeMultikey(fixture.issuerPublicKey);
      const result = verifyCredential({
        token: fixture.credential,
        publicKey: keyBytes,
        currentTime: Math.floor(new Date('2026-06-01T00:00:00.000Z').getTime() / 1000),
      });

      expect(result.iss).toBe(fixture.expected.iss);
      expect(result.sub).toBe(fixture.expected.sub);
      expect(result.type).toBe(fixture.expected.vcType);
    });
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
