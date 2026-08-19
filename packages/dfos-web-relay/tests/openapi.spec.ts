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
  paths: Record<string, Record<string, unknown>>;
  components: { schemas: Record<string, Record<string, unknown>> };
};
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { version: string };

const allowedMethods = new Set(['GET', 'POST', 'PUT', 'DELETE']);

const sortedSetDiff = (left: Set<string>, right: Set<string>) =>
  [...left].filter((path) => !right.has(path)).sort();

// Parameter names are operation-local in OpenAPI. PUT .../{operationCID} and
// GET .../{ref} are one path template, so parity compares template shape.
const normalizePath = (path: string) =>
  path.replace(/:[^/{}]+(?:\{[^}]*\})?/g, ':param').replace(/\{[^}]+\}/g, ':param');

const methodsByPath = (entries: Iterable<[string, Iterable<string>]>): Map<string, Set<string>> => {
  const result = new Map<string, Set<string>>();
  for (const [path, methods] of entries) {
    const normalized = normalizePath(path);
    const existing = result.get(normalized) ?? new Set<string>();
    for (const method of methods) existing.add(method.toUpperCase());
    result.set(normalized, existing);
  }
  return result;
};

const documentedMethods = methodsByPath(
  Object.entries(openapi.paths).map(([path, item]) => [
    path,
    Object.keys(item).filter((method) => allowedMethods.has(method.toUpperCase())),
  ]),
);

const documentedPaths = new Set(documentedMethods.keys());

let registeredPaths: Set<string>;
let registeredMethods: Map<string, Set<string>>;

const object = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;

const responseSchema = (path: string, method: string): Record<string, unknown> => {
  const operation = object(openapi.paths[path]![method]);
  const responses = object(operation['responses']);
  const ok = object(responses['200']);
  const content = object(ok['content']);
  const mediaType = object(content['application/json']);
  const schema = object(mediaType['schema']);
  const ref = schema['$ref'];
  if (typeof ref !== 'string') return schema;
  const name = ref.replace('#/components/schemas/', '');
  return openapi.components.schemas[name]!;
};

describe('openapi', () => {
  beforeAll(async () => {
    const { app } = await createRelay({ store: new MemoryRelayStore() });
    const routes = app.routes.filter(({ method, path }) => {
      if (method === 'ALL' || path === '/*') return false;
      return allowedMethods.has(method);
    });
    registeredMethods = methodsByPath(routes.map(({ method, path }) => [path, [method]]));
    registeredPaths = new Set(registeredMethods.keys());
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

  it('documents the exact registered method set for every path', () => {
    const paths = new Set([...documentedPaths, ...registeredPaths]);
    for (const path of paths) {
      expect(
        [...(documentedMethods.get(path) ?? [])].sort(),
        `OpenAPI methods differ from registered methods for ${path}`,
      ).toEqual([...(registeredMethods.get(path) ?? [])].sort());
    }
  });

  it('declares next on every list-route success envelope', () => {
    const listRoutes = [
      ['/proof/v1/log', 'get'],
      ['/proof/v1/identities/{did}/log', 'get'],
      ['/proof/v1/content/{contentId}/log', 'get'],
      ['/proof/v1/countersignatures/{cid}', 'get'],
      ['/revocations/v1/issuer/{did}', 'get'],
      ['/index/v0/identities', 'get'],
      ['/index/v0/content', 'get'],
      ['/index/v0/credits', 'get'],
      ['/index/v0/countersignatures', 'get'],
      ['/index/v0/credentials', 'get'],
      ['/index/v0/operations', 'get'],
      ['/index/v0/artifacts', 'get'],
      ['/signing/v0/requests', 'get'],
    ] as const;

    for (const [path, method] of listRoutes) {
      const properties = object(responseSchema(path, method)['properties']);
      expect(properties, `${method.toUpperCase()} ${path} response is missing next`).toHaveProperty(
        'next',
      );
    }
  });

  it('keeps info.version in sync with package.json', () => {
    expect(openapi.info.version).toBe(packageJson.version);
  });
});
