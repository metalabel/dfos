/*

  INPUT DISPATCH — paste-a-string → route

  Purely syntactic: dfos-client's resolve() does the network dispatch; this
  decides which view a pasted identifier belongs to before any fetch happens.

*/

export type InputTarget =
  | { kind: 'identity'; id: string }
  | { kind: 'content'; id: string }
  | { kind: 'op'; id: string }
  | { kind: 'key'; key: string }
  | { kind: 'domain'; host: string }
  | null;

// 31-char base32 (protocol id alphabet: lowercase letters + digits 2-9ish);
// stay permissive — the view renders an honest not-found for a bad guess
const CONTENT_ID = /^[a-z0-9]{31}$/;

// CIDv1 base32 (bafy… op/dag-cbor, bafk… raw, etc.)
const CID_V1 = /^baf[a-z2-7]+$/;

/**
 * A `publicKeyMultibase` as this protocol mints them — EXACT, not permissive,
 * unlike the id patterns above. Derived from the encoder rather than guessed:
 * `encodeEd25519Multikey` (dfos-protocol chain/multikey.ts) is
 * `'z' + base58btc([0xed, 0x01] ++ 32 key bytes)`, and 34 bytes whose leading
 * byte is 0xed always encode to exactly 47 base58 digits — the whole value space
 * sits between `z6Mke…` and `z6Mkw…` — so every key is 48 characters with a fixed
 * `z6Mk` head. The two spec fixtures in PROTOCOL.md are both 48 characters.
 *
 * Strict on purpose. A key is the only pasteable identifier with no view of its
 * own to render an honest not-found: the key page ASKS THE RELAY "which
 * identities has this been proved into", and a relay answers a garbage string
 * with an empty page — indistinguishable from a real key nobody has used. So the
 * dispatcher, not the view, is where a non-key is refused, and anything that
 * fails this falls through to the name search.
 *
 * The alphabet is base58btc (no `0`, `O`, `I`, `l`). Nothing else the dispatcher
 * handles can collide: a contentId is 31 lowercase characters, a CID starts `baf`,
 * a DID starts `did:dfos:`, and a hostname requires a dot.
 */
const PUBLIC_KEY_MULTIBASE = /^z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;

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
  // no overlap with the patterns above (48 chars, mixed case, `z6Mk` head), so
  // the position is readability rather than precedence
  if (PUBLIC_KEY_MULTIBASE.test(value)) return { kind: 'key', key: value };
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
    case 'key':
      return `#/key/${target.key}`;
    case 'domain':
      return `#/domain/${target.host}`;
  }
};
