import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
// THE DOGFOOD PATH: exactly what a consumer imports and hands to createRelay —
// the generated JSON artifact behind the package's `./openapi.json` export, not
// a runtime read of the yaml (a bundled consumer has neither a yaml loader nor
// filesystem assets).
import openapiDocument from '../openapi.json';
import { createRelay, MemoryRelayStore } from '../src';

const testDir = dirname(fileURLToPath(import.meta.url));
const openapiPath = resolve(testDir, '../openapi.yaml');
const packageJsonPath = resolve(testDir, '../package.json');

const openapi = parse(readFileSync(openapiPath, 'utf8')) as {
  info: { title: string; version: string };
  paths: Record<string, Record<string, unknown>>;
  components: {
    schemas: Record<string, Record<string, unknown>>;
    securitySchemes: Record<string, Record<string, unknown>>;
  };
};
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as {
  version: string;
  exports: Record<string, unknown>;
  publishConfig: { exports: Record<string, unknown> };
};

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
  let relayApp: Awaited<ReturnType<typeof createRelay>>['app'];

  beforeAll(async () => {
    // the reference relay serves its own document — the route table under test
    // therefore includes /openapi.json, exactly as a configured deployment's does
    const { app } = await createRelay({
      store: new MemoryRelayStore(),
      openapi: { document: openapiDocument },
    });
    relayApp = app;
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

  it('keeps the generated openapi.json byte-identical to the yaml source', () => {
    // the yaml is the source; openapi.json is its committed codegen output
    // (scripts/generate-openapi-json.mjs). Drift here means someone edited the
    // yaml without regenerating, and the served/imported document is stale.
    expect(openapiDocument).toEqual(openapi);
  });

  it('exports the document so a consumer can import and serve it', () => {
    // the reachability half of the dogfood: without this subpath a bundled
    // consumer cannot resolve the document at all
    expect(packageJson.exports['./openapi.json']).toBe('./openapi.json');
    expect(packageJson.publishConfig.exports['./openapi.json']).toBe('./openapi.json');
  });

  it('serves the configured document and advertises it in the well-known', async () => {
    const served = await relayApp.request('http://localhost/openapi.json');
    expect(served.status).toBe(200);
    const document = (await served.json()) as { info: { title: string } };
    expect(document.info.title).toBe(openapi.info.title);

    const wellKnown = (await (
      await relayApp.request('http://localhost/.well-known/dfos-relay')
    ).json()) as { openapi?: string };
    expect(wellKnown.openapi).toBe('/openapi.json');
  });

  it('omits the well-known field and serves nothing when no document is configured', async () => {
    // serving is SHOULD, never MUST — absence of the field is the honest
    // statement that this relay serves no document
    const { app } = await createRelay({ store: new MemoryRelayStore() });
    const wellKnown = (await (
      await app.request('http://localhost/.well-known/dfos-relay')
    ).json()) as Record<string, unknown>;
    expect(wellKnown).not.toHaveProperty('openapi');
    expect((await app.request('http://localhost/openapi.json')).status).toBe(404);
  });

  it('names no host in the canonical document or its committed artifact', () => {
    // The document describes the surface EVERY relay serves, not the address of
    // one. A hardcoded host is wrong for every deployment but the one it names —
    // a client that read `http://localhost:3000` out of a document fetched from
    // a real relay would resolve all 28 operations against localhost. Consumers
    // that import this artifact and serve it from their own origin get OpenAPI's
    // document-URL default, which is right for them; a relay that knows its own
    // authority overwrites the absence at serve time.
    expect(openapi).not.toHaveProperty('servers');
    expect(openapiDocument).not.toHaveProperty('servers');
  });

  it('serves a document whose servers names the relay itself', async () => {
    const cases: [string, string][] = [
      ['relay.example.com', 'https://relay.example.com'],
      ['Relay.Example.com:8443', 'https://relay.example.com:8443'],
      // loopback is the one authority served in the clear
      ['localhost:3000', 'http://localhost:3000'],
      ['127.0.0.1:3000', 'http://127.0.0.1:3000'],
      ['[::1]:3000', 'http://[::1]:3000'],
    ];
    for (const [authority, expected] of cases) {
      const { app } = await createRelay({
        store: new MemoryRelayStore(),
        authority,
        openapi: { document: openapiDocument },
      });
      const served = (await (await app.request('http://localhost/openapi.json')).json()) as {
        servers?: { url: string }[];
      };
      expect(served.servers, `servers for authority ${authority}`).toEqual([{ url: expected }]);
    }
  });

  it('omits servers entirely when no authority is configured', async () => {
    // Nothing honest to write, so nothing is written — and OpenAPI resolves
    // operations against the URL the document was fetched from, which for a
    // self-served document is this relay either way. Absent, not null, not [].
    const { app } = await createRelay({
      store: new MemoryRelayStore(),
      openapi: { document: openapiDocument },
    });
    const served = (await (await app.request('http://localhost/openapi.json')).json()) as Record<
      string,
      unknown
    >;
    expect(served).not.toHaveProperty('servers');
  });

  it('never mutates the caller document while self-describing', async () => {
    // The document a caller passes is very often the shared module-level import
    // of `@metalabel/dfos-web-relay/openapi.json`; two relays in one process must
    // not overwrite each other's self-description through it.
    await createRelay({
      store: new MemoryRelayStore(),
      authority: 'first.example.com',
      openapi: { document: openapiDocument },
    });
    expect(openapiDocument).not.toHaveProperty('servers');

    const { app } = await createRelay({
      store: new MemoryRelayStore(),
      authority: 'second.example.com',
      openapi: { document: openapiDocument },
    });
    const served = (await (await app.request('http://localhost/openapi.json')).json()) as {
      servers?: { url: string }[];
    };
    expect(served.servers).toEqual([{ url: 'https://second.example.com' }]);
  });

  it('advertises a url-form document without registering a route', async () => {
    const { app } = await createRelay({
      store: new MemoryRelayStore(),
      openapi: { url: 'https://docs.example.com/relay.json' },
    });
    const wellKnown = (await (
      await app.request('http://localhost/.well-known/dfos-relay')
    ).json()) as { openapi?: string };
    expect(wellKnown.openapi).toBe('https://docs.example.com/relay.json');
    expect((await app.request('http://localhost/openapi.json')).status).toBe(404);
  });

  it('documents the index filters the routes actually parse', () => {
    const parameters = object(openapi.paths['/index/v0/identities']!['get'])[
      'parameters'
    ] as Record<string, unknown>[];
    expect(parameters.map((parameter) => parameter['name'])).toContain('key');
    // opaque, so no enum/format constraint may creep in — a string is the whole
    // contract, and an undeclared value matches nothing rather than 400ing
    const key = parameters.find((parameter) => parameter['name'] === 'key')!;
    expect(key['required']).toBe(false);
    expect(key['schema']).toEqual({ type: 'string' });
  });

  it('adopts the API-AUTH advertising convention for its security schemes', () => {
    const schemes = openapi.components.securitySchemes;

    // x-dfos-typ is REQUIRED on every scheme:dfos scheme — it names the envelope
    // the scheme carries, mirroring the JWS typ gate on the wire
    expect(schemes['IdentityProof']).toMatchObject({
      type: 'http',
      'x-dfos-typ': 'did:dfos:identity-proof',
    });
    expect(String(schemes['IdentityProof']!['scheme']).toLowerCase()).toBe('dfos');

    // the credential is a token in a named header, nothing bearer-shaped
    expect(schemes['Credential']).toMatchObject({
      type: 'apiKey',
      in: 'header',
      name: 'X-Credential',
    });

    // the relay serves no request-proof route, so no scheme claims that envelope
    for (const scheme of Object.values(schemes)) {
      expect(scheme['x-dfos-typ']).not.toBe('did:dfos:request-proof');
    }

    // the blob reads are the authn/authz split: anonymous under a standing
    // public-read grant, a bare identity proof, or a proof AND a credential
    for (const path of ['/content/{contentId}/blob', '/content/{contentId}/blob/{ref}']) {
      const operation = object(openapi.paths[path]!['get']);
      expect(operation['security'], `${path} security requirements`).toEqual([
        {},
        { IdentityProof: [] },
        { IdentityProof: [], Credential: [] },
      ]);
    }
  });
});
