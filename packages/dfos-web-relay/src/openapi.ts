/*

  SELF-DESCRIPTION — the `servers` a served OpenAPI document names

  The canonical openapi.yaml carries NO `servers` member. It describes the wire
  surface every DFOS relay serves, not the address of any one of them, and a
  document that hardcodes one host is wrong everywhere else: a client that reads
  `http://localhost:3000` out of a document fetched from relay.example.com will
  resolve every operation against localhost and reach nothing. (That is not
  hypothetical — it is the bug this module exists to close.)

  OpenAPI's own default is the correct behavior for a self-served document: with
  `servers` absent, operations resolve against the URL the document was
  retrieved from. A relay that serves its description at /openapi.json is
  therefore already right by saying nothing. This module exists for the strictly
  better case — a relay that KNOWS its own authority can say so, and then the
  document stays right after it is saved to disk, mirrored, or handed to a tool
  that lost track of where it came from.

  THE AUTHORITY IS CONFIGURATION, NEVER THE REQUEST. `servers` is written from
  `RelayOptions.authority` — the same host binding every identity proof is
  checked against — and never from Host, X-Forwarded-Host, or the request URL.
  Those are attacker-supplied, and a document that echoed one back would invite
  a client to sign its next proof against a host of the attacker's choosing.
  When no authority is configured there is nothing honest to write, so the
  member is left absent and OpenAPI's default does the work.

  THE DOCUMENT ALSO DESCRIBES ITSELF, AND THAT ENTRY MOVES TOO. The canonical
  document carries a `/openapi.json` path entry for the operation that returns
  the document — so a deployment that serves it at some other route (a relay
  mounted behind a gateway, a house convention of `/schema.json`) advertised one
  path in its well-known while the served document claimed the document lived at
  another, which 404s. The `servers` rewrite alone did not close that: it fixes
  the ORIGIN every operation resolves against, not the PATH of this one. So the
  self-entry is rekeyed to the route the document is actually served at,
  in place, with its contents untouched and no other path moved.

*/

/**
 * The route the canonical document describes ITSELF at — the `paths` key of its
 * `getOpenApiDocument` operation, and the route `createRelay` serves at when a
 * deployment configures none. One const, so the served copy and the route
 * validation can never disagree about which entry is the self-entry.
 */
export const DEFAULT_OPENAPI_ROUTE = '/openapi.json';

/**
 * Hosts that are reached in the clear. `api:` surfaces are HTTPS surfaces — the
 * CLI refuses to sign a proof for a plaintext request to anything else — so the
 * scheme this module infers from a bare authority is `https` for every host but
 * these.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/**
 * The absolute base URL a request to a relay at `authority` is made against.
 *
 * An authority is a bare `host` or `host:port` (that is what a proof binds to),
 * so the scheme has to be inferred. Loopback is served in the clear during
 * development; everything else is HTTPS, which is the only scheme a DFOS
 * request proof may be sent under anyway.
 *
 * Returns `undefined` when there is no authority to describe.
 */
export const relayBaseUrl = (authority: string | undefined): string | undefined => {
  if (authority === undefined || authority === '') return undefined;
  const host = authority.toLowerCase();
  const hostname = host.startsWith('[')
    ? host.slice(0, host.indexOf(']') + 1)
    : (host.split(':')[0] ?? '');
  return `${LOOPBACK_HOSTS.has(hostname) ? 'http' : 'https'}://${host}`;
};

/**
 * Rekey the document's own path entry to the route it is actually served at.
 *
 * PURE, and deliberately conservative — it fires only when the document says
 * something FALSE about itself. Two cases leave the paths untouched because in
 * both the document is already saying something intentional about `servedRoute`:
 * a document with no default self-entry never described itself here, and one
 * that ALREADY carries an entry at `servedRoute` would have it clobbered.
 *
 * The entry is rekeyed IN PLACE: it keeps its position in the path list and its
 * value by reference, so nothing but the key changes and no other path moves.
 */
const relocateSelfPath = (
  served: Record<string, unknown>,
  servedRoute: string,
): Record<string, unknown> => {
  if (servedRoute === DEFAULT_OPENAPI_ROUTE) return served;
  const paths = served['paths'];
  if (typeof paths !== 'object' || paths === null || Array.isArray(paths)) return served;
  const entries = Object.entries(paths as Record<string, unknown>);
  if (!entries.some(([path]) => path === DEFAULT_OPENAPI_ROUTE)) return served;
  if (entries.some(([path]) => path === servedRoute)) return served;
  return {
    ...served,
    paths: Object.fromEntries(
      entries.map(([path, item]) => [path === DEFAULT_OPENAPI_ROUTE ? servedRoute : path, item]),
    ),
  };
};

/**
 * The document as this relay serves it: a copy of `document` whose `servers`
 * names this relay's own authority — or, when no authority is configured, a copy
 * with no `servers` member at all — and whose self-describing path entry names
 * `servedRoute` rather than the default.
 *
 * A copy, not a mutation: the caller's document is very often the shared import
 * of `@metalabel/dfos-web-relay/openapi.json`, and two relays in one process
 * would otherwise overwrite each other's self-description. Only the top level is
 * cloned — plus `paths`, and only when the self-entry actually moves.
 */
export const selfDescribingDocument = (
  document: unknown,
  authority: string | undefined,
  servedRoute: string = DEFAULT_OPENAPI_ROUTE,
): Record<string, unknown> => {
  const source = document as Record<string, unknown>;
  const served = { ...source };
  const baseUrl = relayBaseUrl(authority);
  if (baseUrl === undefined) {
    delete served['servers'];
  } else {
    served['servers'] = [{ url: baseUrl }];
  }
  return relocateSelfPath(served, servedRoute);
};
