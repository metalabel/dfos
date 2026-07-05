import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { createRelay, MemoryRelayStore } from '../src';

const testDir = dirname(fileURLToPath(import.meta.url));
const openapiPath = resolve(testDir, '../openapi.yaml');
const packageJsonPath = resolve(testDir, '../package.json');

const openapi = parse(readFileSync(openapiPath, 'utf8')) as {
  info: { version: string };
  paths: Record<string, unknown>;
};
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { version: string };

const allowedMethods = new Set(['GET', 'POST', 'PUT', 'DELETE']);

const sortedSetDiff = (left: Set<string>, right: Set<string>) =>
  [...left].filter((path) => !right.has(path)).sort();

const documentedPaths = new Set(
  Object.keys(openapi.paths).map((path) => path.replace(/\{([^}]+)\}/g, ':$1')),
);

let registeredPaths: Set<string>;

describe('openapi', () => {
  beforeAll(async () => {
    const { app } = await createRelay({ store: new MemoryRelayStore() });
    registeredPaths = new Set(
      app.routes
        .filter(({ method, path }) => {
          if (method === 'ALL' || path === '/*') return false;
          if (!allowedMethods.has(method)) return false;
          return true;
        })
        .map(({ path }) => path.replace(/\{[^}]*\}/g, '')),
    );
  });

  it('documents every registered route path', () => {
    expect(
      sortedSetDiff(registeredPaths, documentedPaths),
      'registered paths missing from OpenAPI',
    ).toEqual([]);
  });

  it('registers every documented route path', () => {
    expect(
      sortedSetDiff(documentedPaths, registeredPaths),
      'OpenAPI paths missing from relay routes',
    ).toEqual([]);
  });

  it('keeps info.version in sync with package.json', () => {
    expect(openapi.info.version).toBe(packageJson.version);
  });
});
