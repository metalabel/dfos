/**
 * Validate example chain fixtures
 *
 * Loads the static JSON fixtures from examples/ and verifies them against
 * the protocol implementation. This test is the validator, not the generator.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { decodeMultikey, verifyContentChain, verifyIdentityChain } from '../src/chain';
import type { VerifiedContentChain } from '../src/chain';
import type { VerifiedIdentity } from '../src/chain/schemas';

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
      'content-delete.json',
      'content-lifecycle.json',
      'identity-delete.json',
      'identity-genesis.json',
      'identity-rotation.json',
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

        expect(result.entityId).toBe(fixture.expected.entityId);
        expect(result.isDeleted).toBe(fixture.expected.isDeleted);
        expect(result.currentDocumentCID).toBe(fixture.expected.currentDocumentCID);
        expect(result.length).toBe(fixture.expected.length);
      });
    }
  });
});
