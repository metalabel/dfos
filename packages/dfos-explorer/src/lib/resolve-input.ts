/*

  INPUT DISPATCH — paste-a-string → route

  Purely syntactic: dfos-client's resolve() does the network dispatch; this
  decides which view a pasted identifier belongs to before any fetch happens.

*/

export type InputTarget =
  | { kind: 'identity'; id: string }
  | { kind: 'content'; id: string }
  | { kind: 'op'; id: string }
  | { kind: 'domain'; host: string }
  | null;

// 31-char base32 (protocol id alphabet: lowercase letters + digits 2-9ish);
// stay permissive — the view renders an honest not-found for a bad guess
const CONTENT_ID = /^[a-z0-9]{31}$/;

// CIDv1 base32 (bafy… op/dag-cbor, bafk… raw, etc.)
const CID_V1 = /^baf[a-z2-7]+$/;

/**
 * A hostname, deliberately conservative: labels joined by dots, ending in an
 * alphabetic TLD of two or more characters. The strictness is the point — this
 * branch runs LAST, but a loose pattern would still swallow ordinary searches
 * ("v0.1", "node.js") that belong in the name index, and the search fallback
 * can no longer rescue an input the dispatcher has already claimed.
 */
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

/**
 * Normalize a pasted origin to a bare hostname: a full URL, a host with a
 * trailing path, or a bare host all reduce to the same lookup. Returns '' when
 * the input is not plausibly a host.
 */
export const normalizeHost = (raw: string): string => {
  let value = raw.trim().toLowerCase();
  if (!value) return '';
  // strip a scheme and anything from the first path/query/fragment separator on
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  value = value.replace(/^[^/?#]*@/, ''); // userinfo, if pasted
  const cut = value.search(/[/?#]/);
  if (cut >= 0) value = value.slice(0, cut);
  value = value.replace(/:\d+$/, ''); // port
  value = value.replace(/\.$/, ''); // fully-qualified trailing dot
  return HOSTNAME.test(value) ? value : '';
};

export const dispatchInput = (raw: string): InputTarget => {
  const value = raw.trim();
  if (!value) return null;
  if (value.startsWith('did:dfos:')) return { kind: 'identity', id: value };
  if (CID_V1.test(value)) return { kind: 'op', id: value };
  if (CONTENT_ID.test(value)) return { kind: 'content', id: value };
  // LAST, and after every id pattern: a bare 31-char lowercase string is a
  // contentId, not a hostname, and the id patterns must never lose to a domain
  // guess. A dot is required, so nothing that reaches the name search today
  // starts routing to a domain lookup instead.
  const host = normalizeHost(value);
  if (host) return { kind: 'domain', host };
  return null;
};

export const routeFor = (target: NonNullable<InputTarget>): string => {
  switch (target.kind) {
    case 'identity':
      return `#/did/${target.id}`;
    case 'content':
      return `#/content/${target.id}`;
    case 'op':
      return `#/op/${target.id}`;
    case 'domain':
      return `#/domain/${target.host}`;
  }
};
