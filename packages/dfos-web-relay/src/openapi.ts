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

*/

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
 * The document as this relay serves it: a copy of `document` whose `servers`
 * names this relay's own authority, or — when no authority is configured — a
 * copy with no `servers` member at all.
 *
 * A copy, not a mutation: the caller's document is very often the shared import
 * of `@metalabel/dfos-web-relay/openapi.json`, and two relays in one process
 * would otherwise overwrite each other's self-description. Only the top level
 * is cloned, which is all this touches.
 */
export const selfDescribingDocument = (
  document: unknown,
  authority: string | undefined,
): Record<string, unknown> => {
  const source = document as Record<string, unknown>;
  const served = { ...source };
  const baseUrl = relayBaseUrl(authority);
  if (baseUrl === undefined) {
    delete served['servers'];
  } else {
    served['servers'] = [{ url: baseUrl }];
  }
  return served;
};
