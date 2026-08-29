/*

  KEY DISPLAY IDENTITY — a key is its public key, not the name a chain gave it

  `key_1` is a FRAGMENT. It names a slot on one identity document and means
  nothing off it: two identities can both call a key `key_1` and mean two
  different keys, and one identity can rotate `key_1` and mean two different keys
  itself. The public key is the thing — byte-for-byte the same string on every
  chain that ever declared it, the comparison the relay's `key=` filter makes,
  and the address of the key detail page. So every surface leads with a truncated
  multibase, and the `key_xxx` id sits beside it as metadata. Both link to the
  key's own page, because a reader who recognizes either should land where the
  key lives.

  RESOLUTION IS FROM A DOCUMENT IN HAND, NEVER A GUESS. A JWS header's `kid` is
  `did:dfos:<chain>#key_1` — it carries the slot name, not the key. Turning one
  into a public key needs that identity's declared key set, so:

    document in hand  → the row shows the key
    document not held → the row shows the kid, exactly as it stands

  There is no third behavior. A kid is never resolved against another chain's key
  set, and a key this tab did not read is never rendered as one it did. The
  identity view holds the document it just folded; the content view resolves its
  creator's. An op signed by anybody else's delegated key stays a kid, which is
  the true statement about what we know.

  Matching mirrors lib/profile.ts's signature-check resolver, so display and
  proof agree on which declaration a kid names.

  PROTOCOL LAYER UNCHANGED: `kid` stays opaque in the bytes. This is display.

*/

import { short } from './format';

/** One key as an identity document declares it. */
export interface KeyDeclaration {
  /** the slot name — `key_1`, `#auth-1`, or the full `did:dfos:…#key_1`. */
  id: string;
  publicKeyMultibase: string;
}

/** DID → the keys that identity's document declares. What is not in here is, by
 *  definition, not in hand. */
export type KeyDirectory = ReadonlyMap<string, readonly KeyDeclaration[]>;

/** Nothing in hand — every kid renders as itself. */
export const EMPTY_KEY_DIRECTORY: KeyDirectory = new Map();

/** The three key arrays an identity document declares, flattened in panel order
 *  (auth, assert, controller) — the order the identity view's key table reads,
 *  so both surfaces walk the same list. */
export const declaredKeys = (state: {
  authKeys?: readonly KeyDeclaration[] | undefined;
  assertKeys?: readonly KeyDeclaration[] | undefined;
  controllerKeys?: readonly KeyDeclaration[] | undefined;
}): KeyDeclaration[] => [
  ...(state.authKeys ?? []),
  ...(state.assertKeys ?? []),
  ...(state.controllerKeys ?? []),
];

/** A directory holding ONE identity's document. An empty DID yields an empty
 *  directory rather than a nameless entry — a view with no chain in hand must
 *  resolve nothing. */
export const keyDirectoryOf = (did: string, keys: readonly KeyDeclaration[]): KeyDirectory =>
  did ? new Map([[did, keys]]) : new Map();

/** The DID and fragment a kid names. A kid with no `#` names no slot — a genesis
 *  op carries no kid at all — and resolves to nothing. */
export const splitKid = (kid: string): { did: string; fragment: string } => {
  const i = kid.indexOf('#');
  return i > 0 ? { did: kid.slice(0, i), fragment: kid.slice(i + 1) } : { did: '', fragment: '' };
};

/**
 * A kid → the public key it names, or `null` when that identity's document is
 * not in hand and the key is therefore not known. Matching mirrors
 * lib/profile.ts: a declaration matches on its full id, on the bare fragment, or
 * on any id ending in `#<fragment>` — the three shapes documents write the same
 * slot in. Pure and total.
 */
export const resolveKidPubkey = (kid: string, dir: KeyDirectory): string | null => {
  const { did, fragment } = splitKid(kid);
  if (!did || !fragment) return null;
  const keys = dir.get(did);
  if (!keys) return null;
  const match = keys.find(
    (k) => k.id === kid || k.id === fragment || k.id.endsWith(`#${fragment}`),
  );
  return match?.publicKeyMultibase ?? null;
};

/**
 * A public key at reading density — `z6MkhaXgBZ…mN4h9q`. Ten leading characters
 * is enough to tell two keys on one page apart at a glance and six trailing ones
 * is enough to check a value against a wallet. `cramped` is the 8…4 form for a
 * cell that genuinely cannot hold the full width; it is a last resort and not a
 * second default, because every character dropped is a character of the only
 * identifier this key has.
 */
export const shortPubkey = (multibase: string, cramped = false): string =>
  cramped ? short(multibase, 8, 4) : short(multibase, 10, 6);
